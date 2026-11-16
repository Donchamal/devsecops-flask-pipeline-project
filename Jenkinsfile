
pipeline {
    agent any

    stages {

        stage('Automated Testing & Coverage') {
            steps {
                sh '''
                    docker build -f Dockerfile.test -t devsecops-flask-tests .
                    docker run --name flask-test-run devsecops-flask-tests
                    docker cp flask-test-run:/app/coverage.xml coverage.xml
                    docker rm flask-test-run
                '''
            }
        }

        stage('SonarQube Analysis') {
            steps {
                script {
                    def scannerHome = tool 'SonarScanner'
                    withSonarQubeEnv('SonarQube') {
                        sh "${scannerHome}/bin/sonar-scanner -Dsonar.sources=app.py -Dsonar.tests=. -Dsonar.test.inclusions=**/test_*.py -Dsonar.python.coverage.reportPaths=coverage.xml"
                    }
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -f dockerfile.app -t devsecops-flask .'
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

    post {
        always {
            sh 'docker rm -f flask-test-run || true'
        }
    }
}
