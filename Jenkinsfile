pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/Donchamal/devsecops-flask-pipeline-project.git'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t devsecops-flask .'
            }
        }
    }
}
