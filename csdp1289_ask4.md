Askisi 1

    apiVersion: apiextensions.k8s.io/v1
    kind: CustomResourceDefinition
    metadata:
      name: fruits.hy548.csd.uoc.gr
    spec:
      group: hy548.csd.uoc.gr
      versions:
        - name: v1
          # Each version can be enabled/disabled by Served flag.
          served: true
          # One and only one version must be marked as the storage version.
          storage: true
          schema:
            openAPIV3Schema:
              type: object
              properties:
                spec:
                  type: object
                  properties:
                    origin:
                      type: string
                    count:
                      type: integer
                    grams:
                      type: integer
      scope: Namespaced
      names:
        plural: fruits
        singular: fruit
        kind: Fruit
        shortNames:
        - ct

a)
    kubectl apply -f ask4_1.yaml
    
b) 
    kubectl apply -f apple.yaml
  
c) 
    kubectl get ct -o yaml
  
d) 
    kubectl get fruit #(h fruits)


Askisi 2

a)

      FROM alpine:latest

      RUN apk update
      RUN apk add git
      RUN git clone https://github.com/chazapis/hy548
      RUN apk --update add python3
      RUN apk add --update python3 py3-pip
      RUN pip install --upgrade pip
      RUN pip install -r /hy548/crds/requirements.txt
      RUN apk add curl
      RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
      RUN install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
      CMD ["python3", "/hy548/crds/controller.py"]

b)

      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: flask
      spec:
        replicas: 1
        selector:
          matchLabels:
            app: flask
        template:
          metadata:
            labels:
              app: flask
          spec:
            serviceAccountName: greeting-controller-sa
            containers:
            - name: flask
              image: lefterisboy99/ask4_2:latest
              resources:
                limits:
                  cpu: "200m"
                  memory: "128Mi"
              env:
              - name: MESSAGE
                value: "Hello, world!"

      ---

      apiVersion: v1
      kind: ServiceAccount
      metadata:
        name: greeting-controller-sa

      ---

      apiVersion: rbac.authorization.k8s.io/v1
      kind: ClusterRole
      metadata:
        name: pod-reader-role
      rules:
      - apiGroups: ["*"]
        resources: ["*"]
        verbs: ["*"]

      ---

      apiVersion: rbac.authorization.k8s.io/v1
      kind: ClusterRoleBinding
      metadata:
        name: pod-reader-role-binding
      subjects:
      - kind: ServiceAccount
        name: greeting-controller-sa
        namespace: default
      roleRef:
        kind: ClusterRole
        name: pod-reader-role
        apiGroup: rbac.authorization.k8s.io

ekana kubectl logs kai to onoma tou container kai m evgale ta logs tou kai oti dexete minima apo to crd hello-to-all


Askisi 3

a)

  FROM alpine:latest

  RUN apk update
  RUN apk add git
  RUN git clone https://github.com/chazapis/hy548
  RUN apk --update add python3
  RUN apk add --update python3 py3-pip
  RUN pip install --upgrade pip
  RUN pip install -r /hy548/webhooks/requirements.txt
  RUN rm /hy548/webhooks/controller.py
  COPY ./hy548/webhooks/controller.py /hy548/webhooks/
  CMD ["python3", "/hy548/webhooks/controller.py"]

b)

  apiVersion: v1
  kind: Namespace
  metadata:
    name: custom-label-injector
    labels:
      app: custom-label-injector
  ---
  apiVersion: cert-manager.io/v1
  kind: Issuer
  metadata:
    name: issuer-selfsigned
    namespace: custom-label-injector
    labels:
      app: custom-label-injector
  spec:
    selfSigned: {}
  ---
  apiVersion: cert-manager.io/v1
  kind: Certificate
  metadata:
    name: controller-certificate
    namespace: custom-label-injector
    labels:
      app: custom-label-injector
  spec:
    secretName: controller-certificate
    duration: 87600h
    commonName: controller.custom-label-injector.svc
    dnsNames:
    - controller.custom-label-injector.svc
    privateKey:
      algorithm: RSA
      size: 2048
    issuerRef:
      name: issuer-selfsigned
  ---
  apiVersion: v1
  kind: Service
  metadata:
    name: controller
    namespace: custom-label-injector
    labels:
      app: custom-label-injector
  spec:
    type: ClusterIP
    ports:
      - port: 8000
        name: https
    selector:
      app: custom-label-injector

  ---

  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: controller
    namespace: custom-label-injector
    labels:
      app: custom-label-injector
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: custom-label-injector
    template:
      metadata:
        labels:
          app: custom-label-injector
      spec:
        containers:
        - image: lefterisboy99/ask4_3:latest
          name: proxy
          env:
          - name: NGINX_ENTRYPOINT_QUIET_LOGS
            value: "1"
          ports:
          - containerPort: 8000
            name: https
          volumeMounts:
          - name: controller-certificate-volume
            mountPath: /etc/ssl/keys
            readOnly: true
        volumes:
        - name: controller-certificate-volume
          secret:
            secretName: controller-certificate

  ---
  apiVersion: admissionregistration.k8s.io/v1
  kind: MutatingWebhookConfiguration
  metadata:
    name: custom-label-injector
    namespace: custom-label-injector
    labels:
      app: custom-label-injector
    annotations:
      cert-manager.io/inject-ca-from: custom-label-injector/controller-certificate
  webhooks:
    - name: controller.custom-label-injector.svc
      clientConfig:
        service:
          name: controller
          namespace: custom-label-injector
          path: "/mutate"
      rules:
        - operations: ["CREATE"]
          apiGroups: ["*"]
          apiVersions: ["*"]
          resources: ["pods", "deployments"]
      namespaceSelector:
        matchLabels:
          custom-label-injector: enabled
      admissionReviewVersions: ["v1", "v1beta1"]
      sideEffects: None
      failurePolicy: Fail




gia na to testaro ekana ta commands pou lete sto readme kai eida oti dimiourgountai pods custom-label gia namespace xoris na xreiastei na grapso kati episis egrapsa kai 2 grammes stin python:

  #!/usr/bin/env python

  import jsonpatch
  import copy
  import base64
  import os

  from flask import Flask, request, jsonify

  app = Flask(__name__)

  def inject_label(yaml_data, label):
      for part in yaml_data:
          if 'labels' not in part['metadata']:
              part['metadata']['labels'] = {}
          part['metadata']['labels'][label] = 'true'

  @app.route('/mutate', methods=['POST'])
  def mutate():
      data = request.get_json()
      uid = data['request']['uid']
      service = copy.deepcopy(data['request']['object'])
      inject_label([service], os.getenv('CUSTOM_LABEL', 'custom-label'))
      patch = jsonpatch.JsonPatch.from_diff(data['request']['object'], service)
      encoded_patch = base64.b64encode(patch.to_string().encode('utf-8')).decode('utf-8')

      return jsonify({'apiVersion': 'admission.k8s.io/v1',
                    'kind': 'AdmissionReview',
                    'response': {'uid': uid,
                                  'allowed': True,
                                  'status': {'message': 'Adding extra label'},
                                  'patchType': 'JSONPatch',
                                  'patch': encoded_patch}})

  if __name__ == '__main__':
      context = ('/etc/ssl/keys/tls.crt', '/etc/ssl/keys/tls.key')#1
      app.run(host='0.0.0.0', port=8000, ssl_context=context)#2
