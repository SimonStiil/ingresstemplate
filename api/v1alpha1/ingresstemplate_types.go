/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IngressTemplateSpec defines the desired state of IngressTemplate
type IngressTemplateSpec struct {
	// +listType=atomic
	// +optional
	SecretReplacements []Replacement `json:"secretReplacement,omitempty" protobuf:"bytes,2,rep,name=secretReplacement"`

	// +listType=atomic
	// +optional
	ConfigMapReplacements []Replacement `json:"configmapReplacement,omitempty" protobuf:"bytes,2,rep,name=configmapReplacement"`

	// copied from networking.v1.types.go "type IngressSpec struct"

	// IngressClassName is the name of the IngressClass cluster resource. The
	// associated IngressClass defines which controller will implement the
	// resource. This replaces the deprecated `kubernetes.io/ingress.class`
	// annotation. For backwards compatibility, when that annotation is set, it
	// must be given precedence over this field. The controller may emit a
	// warning if the field and annotation have different values.
	// Implementations of this API should ignore Ingresses without a class
	// specified. An IngressClass resource may be marked as default, which can
	// be used to set a default value for this field. For more information,
	// refer to the IngressClass documentation.
	// +optional
	IngressClassName *string `json:"ingressClassName,omitempty" protobuf:"bytes,4,opt,name=ingressClassName"`

	// DefaultBackend is the backend that should handle requests that don't
	// match any rule. If Rules are not specified, DefaultBackend must be specified.
	// If DefaultBackend is not set, the handling of requests that do not match any
	// of the rules will be up to the Ingress controller.
	// +optional
	DefaultBackend *networkingv1.IngressBackend `json:"defaultBackend,omitempty" protobuf:"bytes,1,opt,name=defaultBackend"`

	// TLS configuration. Currently the Ingress only supports a single TLS
	// port, 443. If multiple members of this list specify different hosts, they
	// will be multiplexed on the same port according to the hostname specified
	// through the SNI TLS extension, if the ingress controller fulfilling the
	// ingress supports SNI.
	// +listType=atomic
	// +optional
	TLS []networkingv1.IngressTLS `json:"tls,omitempty" protobuf:"bytes,2,rep,name=tls"`

	// A list of host rules used to configure the Ingress. If unspecified, or
	// no rule matches, all traffic is sent to the default backend.
	// +listType=atomic
	// +optional
	Rules []networkingv1.IngressRule `json:"rules,omitempty" protobuf:"bytes,3,rep,name=rules"`
}

type Replacement struct {

	// The name of the object in the templates namespace to select from.
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`

	// What should be replaced in path or host.
	// +optional
	Selector string `json:"selector" protobuf:"bytes,2,opt,name=selector"`
}

// IngressTemplateStatus defines the observed state of IngressTemplate
type IngressTemplateStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Condition string `json:"condition,omitempty" protobuf:"bytes,1,rep,name=conditions"`

	Secrets    []ObjectStatus `json:"secrets,omitempty" protobuf:"bytes,2,rep,name=secrets"`
	ConfigMaps []ObjectStatus `json:"configmaps,omitempty" protobuf:"bytes,2,rep,name=configmaps"`
}

type ObjectStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Name   string `json:"name,omitempty" protobuf:"bytes,1,key,name=name"`
	Status string `json:"status,omitempty" protobuf:"bytes,2,key,name=status"`
	Sha1   string `json:"sha,omitempty" protobuf:"bytes,3,key,name=sha"`
}

const (
	// Conditions
	AwaitingSecret    string = "AwaitingSecret"
	AwaitingConfigMap string = "AwaitingConfigMap"
	Created           string = "Created"
	Failed            string = "Failed"
	New               string = "New"

	// SecretStatus
	NotFound string = "NotFound"
	Found    string = "Found"
	Changed  string = "Changed"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IngressTemplate is the Schema for the ingresstemplates API
type IngressTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IngressTemplateSpec   `json:"spec,omitempty"`
	Status IngressTemplateStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IngressTemplateList contains a list of IngressTemplate
type IngressTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IngressTemplate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IngressTemplate{}, &IngressTemplateList{})
}
