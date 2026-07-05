pipeline {
    agent any

    stages {

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t devsecops-flask .'
            }
        }

        stage('Trivy Filesystem Scan') {
            steps {
                sh 'trivy fs .'
            }
        }

        stage('Trivy Image Scan') {
            steps {
                sh 'trivy image devsecops-flask'
            }
        }

    }
}