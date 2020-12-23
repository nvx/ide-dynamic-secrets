package com.github.martinsucha.idedynamicsecrets

import com.intellij.database.access.DatabaseCredentials
import com.intellij.database.dataSource.DatabaseAuthProvider
import com.intellij.database.dataSource.DatabaseConnectionInterceptor
import com.intellij.database.dataSource.LocalDataSource
import com.intellij.database.dataSource.url.template.MutableParametersHolder
import com.intellij.database.dataSource.url.template.ParametersHolder
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogPanel
import com.intellij.ui.layout.panel
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import javax.swing.JComponent
import javax.swing.event.DocumentListener

const val DATABASE_CREDENTIAL_PROVIDER_ID = "com.github.martinsucha.idedynamicsecrets"
const val DATABASE_PATH_PROPERTY = "com.github.martinsucha.idedynamicsecrets.path"
const val DATABASE_USERNAME_KEY_PROPERTY = "com.github.martinsucha.idedynamicsecrets.usernameKey"
const val DATABASE_PASSWORD_KEY_PROPERTY = "com.github.martinsucha.idedynamicsecrets.pwdKey"

class DynamicSecretsAuthCredentialsProvider : DatabaseAuthProvider {
    override fun intercept(
        proto: DatabaseConnectionInterceptor.ProtoConnection,
        silent: Boolean
    ): CompletionStage<DatabaseConnectionInterceptor.ProtoConnection>? {
        return CompletableFuture.supplyAsync {
            val path = proto.connectionPoint.additionalJdbcProperties[DATABASE_PATH_PROPERTY]
            if (path == null || path == "") {
                throw RuntimeException("vault path is not specified")
            }
            val usernameKey = proto.connectionPoint.additionalJdbcProperties[DATABASE_USERNAME_KEY_PROPERTY]
            if (usernameKey == null || usernameKey == "") {
                throw RuntimeException("vault username key is not specified")
            }
            val passwordKey = proto.connectionPoint.additionalJdbcProperties[DATABASE_PASSWORD_KEY_PROPERTY]
            if (passwordKey == null || passwordKey == "") {
                throw RuntimeException("vault password key is not specified")
            }

            val vault = proto.runConfiguration.project.getService(Vault::class.java)
            val token = vault.getToken()

            val secret = vault.fetchSecret(token, path)

            if (!secret.containsKey(usernameKey)) {
                throw RuntimeException("key $usernameKey is not present in secret")
            }

            if (!secret.containsKey(passwordKey)) {
                throw RuntimeException("key $passwordKey is not present in secret")
            }

            proto.connectionProperties["user"] = secret[usernameKey]
            proto.connectionProperties["password"] = secret[passwordKey]

            proto
        }
    }

    override fun getId(): String = DATABASE_CREDENTIAL_PROVIDER_ID

    override fun getDisplayName(): String = "Dynamic Secrets"

    override fun isApplicable(dataSource: LocalDataSource): Boolean = true

    override fun isApplicableAsDefault(dataSource: LocalDataSource): Boolean = true

    override fun createWidget(
        project: Project?,
        credentials: DatabaseCredentials,
        dataSource: LocalDataSource
    ): DatabaseAuthProvider.AuthWidget {
        return DynamicSecretsAuthWidget()
    }
}

data class DatabaseSecretConfiguration(
    var path : String = "",
    var usernameKey : String = "username",
    var passwordKey : String = "password",
)

class DynamicSecretsAuthWidget : DatabaseAuthProvider.AuthWidget {
    private val configuration = DatabaseSecretConfiguration()
    private val panel = createPanel()

    private fun createPanel(): DialogPanel = panel {
        row("Secret path:") {
            textField(configuration::path).focused()
        }
        row("Username secret value:") {
            textField(configuration::usernameKey)
        }
        row("Password secret value:") {
            textField(configuration::passwordKey)
        }
    }

    override fun onChanged(p0: DocumentListener) {}

    override fun save(dataSource: LocalDataSource, copyCredentials: Boolean) {
        panel.apply()
        dataSource.additionalJdbcProperties[DATABASE_PATH_PROPERTY] = configuration.path
        dataSource.additionalJdbcProperties[DATABASE_USERNAME_KEY_PROPERTY] = configuration.usernameKey
        dataSource.additionalJdbcProperties[DATABASE_PASSWORD_KEY_PROPERTY] = configuration.passwordKey
    }

    override fun reset(dataSource: LocalDataSource, resetCredentials: Boolean) {
        configuration.path = dataSource.additionalJdbcProperties[DATABASE_PATH_PROPERTY] ?: ""
        configuration.usernameKey = dataSource.additionalJdbcProperties[DATABASE_USERNAME_KEY_PROPERTY] ?: "username"
        configuration.passwordKey = dataSource.additionalJdbcProperties[DATABASE_PASSWORD_KEY_PROPERTY] ?: "password"
        panel.reset()
    }

    override fun isPasswordChanged(): Boolean = false

    override fun hidePassword() {}

    override fun reloadCredentials() {}

    override fun getComponent(): JComponent = panel

    override fun getPreferredFocusedComponent(): JComponent = panel.preferredFocusedComponent!!

    override fun forceSave() {}

    override fun updateFromUrl(holder: ParametersHolder) {}

    override fun updateUrl(holder: MutableParametersHolder) {}

}