pipeline {
    agent any

    tools {
        sonarQube 'SonarScanner'
    }

    stages {

        stage('SonarQube Analysis') {
            steps {
                script {
                    def scannerHome = tool 'SonarScanner'
                    withSonarQubeEnv('SonarQube') {
                        sh """
                            ${scannerHome}/bin/sonar-scanner
                        """
                    }
                }
            }
        }

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