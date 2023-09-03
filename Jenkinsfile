properties([disableConcurrentBuilds(), buildDiscarder(logRotator(artifactDaysToKeepStr: '5', artifactNumToKeepStr: '5', daysToKeepStr: '5', numToKeepStr: '5'))])

@Library('pipeline-library')
import dk.stiil.pipeline.Constants

podTemplate(yaml: '''
    apiVersion: v1
    kind: Pod
    spec:
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:debug
        command:
        - sleep
        args: 
        - 99d
        volumeMounts:
        - name: kaniko-secret
          mountPath: /kaniko/.docker
      - name: golang
        image: golang:bookworm
        command:
        - sleep
        args: 
        - 99d
      restartPolicy: Never
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
    container('kaniko') {
      stage('Build Docker Image') {
        sh '''
          /kaniko/executor --force --context `pwd` --destination docker.io/simonstiil/ingresstemplate:$BRANCH_NAME
        '''
      }
    }
 
  }
}