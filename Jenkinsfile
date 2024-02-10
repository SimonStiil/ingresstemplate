properties([disableConcurrentBuilds(), buildDiscarder(logRotator(artifactDaysToKeepStr: '5', artifactNumToKeepStr: '5', daysToKeepStr: '5', numToKeepStr: '5'))])

@Library('pipeline-library')
import dk.stiil.pipeline.Constants

podTemplate(yaml: '''
    apiVersion: v1
    kind: Pod
    spec:
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:v1.20.0-debug
        command:
        - sleep
        args: 
        - 99d
        volumeMounts:
        - name: kaniko-secret
          mountPath: /kaniko/.docker
      - name: golang
        image: golang:1.22.0-bookworm
        command:
        - sleep
        args: 
        - 99d
      restartPolicy: Never
      nodeSelector: 
        kubernetes.io/arch: amd64
      volumes:
      - name: kaniko-secret
        secret:
          secretName: dockerhub-dockercred
          items:
          - key: .dockerconfigjson
            path: config.json
''') {
  node(POD_LABEL) {
    stage('checkout SCM') {  
      checkout scm
    }
    container('golang') {
      stage('UnitTests & Build') {
        sh '''
          make
        '''
      }
    }
    if ( ! isPRBranch() ) {
      container('kaniko') {
        stage('Build Docker Image') {
          sh '''
            /kaniko/executor --force --context `pwd` --log-format text --destination docker.io/simonstiil/ingresstemplate:$BRANCH_NAME
          '''
        }
      }
    }
 
  }
}