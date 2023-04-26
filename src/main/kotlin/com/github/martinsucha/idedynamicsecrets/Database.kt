package com.github.martinsucha.idedynamicsecrets

import com.intellij.database.access.DatabaseCredentials
import com.intellij.database.dataSource.*
import com.intellij.database.dataSource.url.template.MutableParametersHolder
import com.intellij.database.dataSource.url.template.ParametersHolder
import com.intellij.openapi.Disposable
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogPanel
import com.intellij.openapi.util.Disposer
import com.intellij.ui.layout.panel
import kotlinx.coroutines.runBlocking
import java.util.WeakHashMap
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import javax.swing.JComponent

const val DATABASE_CREDENTIAL_PROVIDER_ID = "com.github.martinsucha.idedynamicsecrets"
const val DATABASE_PATH_PROPERTY = "com.github.martinsucha.idedynamicsecrets.path"
const val DATABASE_USERNAME_KEY_PROPERTY = "com.github.martinsucha.idedynamicsecrets.usernameKey"
const val DATABASE_PASSWORD_KEY_PROPERTY = "com.github.martinsucha.idedynamicsecrets.pwdKey"

class DynamicSecretsAuthCredentialsProvider : DatabaseAuthProvider {
    private val lock = Any()
    private val protoLeases = WeakHashMap<DatabaseConnectionInterceptor.ProtoConnection, DatabaseLease>()

    override fun intercept(
        proto: DatabaseConnectionInterceptor.ProtoConnection,
        silent: Boolean
    ): CompletionStage<DatabaseConnectionInterceptor.ProtoConnection>? {
        return CompletableFuture.supplyAsync {
            val path = proto.connectionPoint.getAdditionalProperty(DATABASE_PATH_PROPERTY)
            if (path == null || path == "") {
                throw ConfigurationException("vault path is not specified")
            }
            val usernameKey = proto.connectionPoint.getAdditionalProperty(DATABASE_USERNAME_KEY_PROPERTY)
            if (usernameKey == null || usernameKey == "") {
                throw ConfigurationException("vault username key is not specified")
            }
            val passwordKey = proto.connectionPoint.getAdditionalProperty(DATABASE_PASSWORD_KEY_PROPERTY)
            if (passwordKey == null || passwordKey == "") {
                throw ConfigurationException("vault password key is not specified")
            }

            val vault = proto.project.getService(Vault::class.java)
            val token = vault.getToken()

            val secret = vault.getClient().use {
                runBlocking {
                    it.fetchSecret(token, path)
                }
            }
            val lease = DatabaseLease(vault, secret.leaseID, proto.project)
            Disposer.register(vault, lease)

            if (!secret.data.containsKey(usernameKey)) {
                Disposer.dispose(lease)
                throw VaultException("key $usernameKey is not present in secret")
            }

            if (!secret.data.containsKey(passwordKey)) {
                Disposer.dispose(lease)
                throw VaultException("key $passwordKey is not present in secret")
            }

            synchronized(lock) {
                protoLeases[proto] = lease
            }

            proto.connectionProperties["user"] = secret.data[usernameKey]
            proto.connectionProperties["password"] = secret.data[passwordKey]

            proto
        }
    }

    override fun getId(): String = DATABASE_CREDENTIAL_PROVIDER_ID

    override fun getDisplayName(): String = "Dynamic Secrets"

    override fun isApplicable(dataSource: LocalDataSource, level: DatabaseAuthProvider.ApplicabilityLevel): Boolean = true

    override fun createWidget(
        project: Project?,
        credentials: DatabaseCredentials,
        config: DatabaseConnectionConfig
    ): DatabaseAuthProvider.AuthWidget {
        return DynamicSecretsAuthWidget()
    }

    override fun handleConnected(
        connection: DatabaseConnectionCore,
        proto: DatabaseConnectionInterceptor.ProtoConnection
    ): CompletionStage<*>? {
        // Move the lease from proto to connection.
        val lease = synchronized(lock) {
            protoLeases.remove(proto)!!
        }
        val leaseHolder = proto.project.getService(DatabaseConnectionLeaseHolder::class.java)
        leaseHolder.registerConnection(connection, lease)
        return super.handleConnected(connection, proto)
    }

    override fun handleConnectionFailure(
        proto: DatabaseConnectionInterceptor.ProtoConnection,
        e: Throwable,
        silent: Boolean,
        attempt: Int
    ): CompletionStage<DatabaseConnectionInterceptor.ProtoConnection>? {
        // Revoke the credentials as the connection failed.
        val lease = synchronized(lock) {
            protoLeases.remove(proto)!!
        }
        Disposer.dispose(lease)
        return super.handleConnectionFailure(proto, e, silent, attempt)
    }
}

data class DatabaseSecretConfiguration(
    var path: String = "",
    var usernameKey: String = "username",
    var passwordKey: String = "password",
)

@Suppress("TooManyFunctions")
class DynamicSecretsAuthWidget : DatabaseAuthProvider.AuthWidget {
    private val configuration = DatabaseSecretConfiguration()
    private val panel = createPanel()

    private fun createPanel(): DialogPanel = panel {
        row("Secret path:") {
            textField(configuration::path).focused()
        }
        row("Username key:") {
            textField(configuration::usernameKey)
        }
        row("Password key:") {
            textField(configuration::passwordKey)
        }
    }

    override fun onChanged(p0: Runnable) {
        // no-op. Do we need to implement this?
    }

    override fun save(config: DatabaseConnectionConfig, copyCredentials: Boolean) {
        panel.apply()
        config.setAdditionalProperty(DATABASE_PATH_PROPERTY,configuration.path)
        config.setAdditionalProperty(DATABASE_USERNAME_KEY_PROPERTY, configuration.usernameKey)
        config.setAdditionalProperty(DATABASE_PASSWORD_KEY_PROPERTY, configuration.passwordKey)
    }

    override fun reset(point: DatabaseConnectionPoint, resetCredentials: Boolean) {
        configuration.path = point.getAdditionalProperty(DATABASE_PATH_PROPERTY) ?: ""
        configuration.usernameKey = point.getAdditionalProperty(DATABASE_USERNAME_KEY_PROPERTY) ?: "username"
        configuration.passwordKey = point.getAdditionalProperty(DATABASE_PASSWORD_KEY_PROPERTY) ?: "password"
        panel.reset()
    }

    override fun isPasswordChanged(): Boolean = false

    override fun hidePassword() {
        // no-op
    }

    override fun reloadCredentials() {
        // no-op
    }

    override fun getComponent(): JComponent = panel

    override fun getPreferredFocusedComponent(): JComponent = panel.preferredFocusedComponent!!

    override fun forceSave() {
        // no-op
    }

    override fun updateFromUrl(holder: ParametersHolder) {
        // no-op
    }

    override fun updateUrl(holder: MutableParametersHolder) {
        // no-op
    }
}

class DatabaseLease(private val vault: Vault, private val leaseID: String, private val project: Project) : Disposable {
    override fun dispose() {
        val runnable = Runnable {
            try {
                val token = vault.getToken()
                vault.getClient().use {
                    runBlocking {
                        it.revokeLease(token, leaseID)
                    }
                }
            } catch (e: VaultException) {
                notifyError(project, "Error revoking lease: ${e.message}")
            }
        }
        ProgressManager.getInstance().runProcessWithProgressSynchronously(
            runnable,
            "Revoking Vault Lease",
            false,
            project,
            null
        )
    }
}

class DatabaseConnectionListener : DatabaseConnectionManager.Listener {
    override fun connectionChanged(connection: DatabaseConnection, added: Boolean) {
        val leaseHolder = connection.configuration.project.getService(DatabaseConnectionLeaseHolder::class.java)
        if (!added) {
            val lease = leaseHolder.unregisterConnection(connection)
            if (lease != null) {
                Disposer.dispose(lease)
            }
        }
    }
}

class DatabaseConnectionLeaseHolder(@Suppress("UNUSED_PARAMETER") project: Project) {

    private val lock = Any()
    private val leaseByConnection = mutableMapOf<DatabaseConnectionCore, Disposable>()

    fun registerConnection(connection: DatabaseConnectionCore, lease: DatabaseLease) {
        synchronized(lock) {
            leaseByConnection[connection] = lease
        }
    }

    fun unregisterConnection(connection: DatabaseConnectionCore): Disposable? {
        synchronized(lock) {
            return leaseByConnection.remove(connection)
        }
    }
}
