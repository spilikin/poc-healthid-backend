module.exports = {
    devServer: {
        proxy: {
            '^/api': {
              target: 'http://localhost:8000',
              changeOrigin: true
            },
        }      
    },
    pages: {
        SignIn: {
            title: "HealthID Sign In",
            entry: 'src/pages/SignIn/index.ts',
            template: 'templates/index.html',
        },
        Account: {
            title: "HealthID Account",
            entry: 'src/pages/Account/index.ts',
            template: 'templates/index.html',
        }
    }
}