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

package controller

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/fields" // Required for Watching
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types" // Required for Watching

	"k8s.io/client-go/tools/record"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder" // Required for Watching
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler" // Required for Watching
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate" // Required for Watching
	"sigs.k8s.io/controller-runtime/pkg/reconcile" // Required for Watching

	// Required for Watching
	networkingv1alpha1 "stiil.dk/ingresstemplate/api/v1alpha1"
)

const (
	secretNameField    = ".spec.secretReplacement.name"
	configmapNameField = ".spec.configMapReplacement.name"
	deploymentOwnerKey = ".metadata.controller"
)

// IngressTemplateReconciler reconciles a IngressTemplate object
type IngressTemplateReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

type Statuses struct {
	Secrets    map[string]networkingv1alpha1.ObjectStatus
	ConfigMaps map[string]networkingv1alpha1.ObjectStatus
}

type Replacement struct {
	Selector    string
	Replacement string
	Sha1        string
	//	Status      networkingv1alpha1.ObjectStatus
}

//+kubebuilder:rbac:groups=networking.stiil.dk,resources=ingresstemplates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.stiil.dk,resources=ingresstemplates/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.stiil.dk,resources=ingresstemplates/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the IngressTemplate object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *IngressTemplateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.WithValues("namespace", req.NamespacedName)

	// Fetch Working Object
	log.Info("fetching IngressTemplate resource in ")
	var ingressTemplate networkingv1alpha1.IngressTemplate
	if err := r.Get(ctx, req.NamespacedName, &ingressTemplate); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info(fmt.Sprintf("Reconcile - Resource not found, Deleted?"))
			return ctrl.Result{}, client.IgnoreNotFound(err)
		} else {
			log.Error(err, "Unable to fetch IngressTemplate")
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}
	statuses := buildStatus(&ingressTemplate)

	// Do Cleanup of old stuff
	// log.WithValues("ingresstemplate", ingressTemplate.Name)
	if err := r.cleanupOwnedResources(ctx, &ingressTemplate); err != nil {
		log.Error(err, "failed to clean up old Owned resources for this IngressTemplate")
		return ctrl.Result{}, err
	}
	replacements := []Replacement{} //:= make([]Replacement, len(ingressTemplate.Spec.SecretReplacements)+len(ingressTemplate.Spec.ConfigMapReplacements))

	// Get replacements for secrets
	var missingSecret string
	handle := false
	for _, secretReplacement := range ingressTemplate.Spec.SecretReplacements {
		secret := corev1.Secret{}
		err := r.Get(ctx, client.ObjectKey{Namespace: ingressTemplate.Namespace, Name: secretReplacement.Name}, &secret)
		statusKey := secretReplacement.Name + "-" + secretReplacement.Selector
		currentSecretStatus := statuses.Secrets[statusKey]
		if apierrors.IsNotFound(err) {
			currentSecretStatus.Status = networkingv1alpha1.NotFound
			log.Error(err, fmt.Sprintf("Failed to find Secret %q", secretReplacement.Name))
			missingSecret = secretReplacement.Name
			statuses.Secrets[statusKey] = currentSecretStatus
			continue
		}
		if err != nil {
			log.Error(err, "Unable to fetch Secret")
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		currentSecretStatus.Status = networkingv1alpha1.Found
		selector := secretReplacement.Selector
		hash := sha1.New()
		hash.Write([]byte(selector))
		replacementDataByte := secret.Data[selector]
		hash.Write(replacementDataByte)
		replacementData := string(replacementDataByte)
		result := hash.Sum(nil)
		sha1 := hex.EncodeToString(result[:7])
		sha1Changed := currentSecretStatus.Sha1 != sha1

		if currentSecretStatus.Status == networkingv1alpha1.Found {
			if sha1Changed {
				currentSecretStatus.Status = networkingv1alpha1.Changed
				handle = true
			}
		} else {
			if !sha1Changed {
				currentSecretStatus.Status = networkingv1alpha1.Found
				handle = true
			} else {
				currentSecretStatus.Status = networkingv1alpha1.Changed
				handle = true
			}
		}
		currentSecretStatus.Sha1 = sha1
		statuses.Secrets[statusKey] = currentSecretStatus

		replacement := Replacement{Selector: selector, Replacement: replacementData, Sha1: sha1}
		log.Info("Reconcile secretReplacement: " + fmt.Sprintf("%+v\n", replacement) + " " + fmt.Sprintf("sha1Changed: %v Status: %v\n", sha1Changed, currentSecretStatus.Status))
		replacements = append(replacements, replacement)

	}

	// Get replacements for configmaps
	var missingConfigMap string
	for _, configMapReplacement := range ingressTemplate.Spec.ConfigMapReplacements {
		configMap := corev1.ConfigMap{}
		err := r.Get(ctx, client.ObjectKey{Namespace: ingressTemplate.Namespace, Name: configMapReplacement.Name}, &configMap)
		statusKey := configMapReplacement.Name + "-" + configMapReplacement.Selector
		currentConfigMapStatus := statuses.ConfigMaps[statusKey]
		if apierrors.IsNotFound(err) {
			currentConfigMapStatus.Status = networkingv1alpha1.NotFound
			log.Error(err, fmt.Sprintf("Failed to find ConfigMap %q", configMapReplacement.Name))
			missingConfigMap = configMapReplacement.Name
			statuses.ConfigMaps[statusKey] = currentConfigMapStatus
			continue
		}
		if err != nil {
			log.Error(err, "Unable to fetch Secret")
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		currentConfigMapStatus.Status = networkingv1alpha1.Found
		selector := configMapReplacement.Selector
		hash := sha1.New()
		hash.Write([]byte(selector))
		replacementData := configMap.Data[selector]
		hash.Write([]byte(replacementData))
		result := hash.Sum(nil)
		sha1 := hex.EncodeToString(result[:7])
		sha1Changed := currentConfigMapStatus.Sha1 != sha1

		if currentConfigMapStatus.Status == networkingv1alpha1.Found {
			if sha1Changed {
				currentConfigMapStatus.Status = networkingv1alpha1.Changed
				handle = true
			}
		} else {
			if !sha1Changed {
				currentConfigMapStatus.Status = networkingv1alpha1.Found
				handle = true
			} else {
				currentConfigMapStatus.Status = networkingv1alpha1.Changed
				handle = true
			}
		}
		currentConfigMapStatus.Sha1 = sha1
		statuses.ConfigMaps[statusKey] = currentConfigMapStatus

		replacement := Replacement{Selector: selector, Replacement: replacementData, Sha1: sha1}
		log.Info("Reconcile configMapReplacement: " + fmt.Sprintf("%+v\n", replacement) + " " + fmt.Sprintf("sha1Changed: %v Status: %v\n", sha1Changed, currentConfigMapStatus.Status))
		replacements = append(replacements, replacement)
	}
	if !handle {
		log.Info("no changes stopping Reconcile")
		return ctrl.Result{}, nil
	}
	setResourcesStatus(&ingressTemplate, statuses)
	// If Create new Ingress Resource
	ingress := networkingv1.Ingress{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: ingressTemplate.Namespace, Name: ingressTemplate.Name}, &ingress)
	if apierrors.IsNotFound(err) {

		// On Missing Depndent Resources
		if missingSecret != "" {
			log.Error(err, "failed to create Ingress resource due to missing secret: "+missingSecret)
			ingressTemplate.Status.Condition = networkingv1alpha1.AwaitingSecret
			r.Status().Update(ctx, &ingressTemplate)
			return ctrl.Result{}, err
		}
		if missingConfigMap != "" {
			log.Error(err, "failed to create Ingress resource due to missing configmap: "+missingConfigMap)
			ingressTemplate.Status.Condition = networkingv1alpha1.AwaitingConfigMap
			r.Status().Update(ctx, &ingressTemplate)
			return ctrl.Result{}, err
		}

		// Create new Ingress Resource
		log.Info("could not find existing Ingress for IngressTemplate, creating one...")
		ingress = *buildIngress(&log, &ingressTemplate, &replacements)
		if err := r.Client.Create(ctx, &ingress); err != nil {
			log.Error(err, "failed to create Ingress resource")
			ingressTemplate.Status.Condition = networkingv1alpha1.Failed
			r.Status().Update(ctx, &ingressTemplate)
			return ctrl.Result{}, err
		}
		r.Recorder.Eventf(&ingressTemplate, corev1.EventTypeNormal, "Created", "Created Ingress %q", ingress.Name)
		log.Info("created Ingress resource for IngressTemplate")
		ingressTemplate.Status.Condition = networkingv1alpha1.Created
		r.Status().Update(ctx, &ingressTemplate)
		return ctrl.Result{}, nil
	}

	// Update Ingress Resource
	updateRules(&log, &ingress, &ingressTemplate, &replacements)
	if err := r.Client.Update(ctx, &ingress); err != nil {
		log.Error(err, "failed to update Ingress resource")
		ingressTemplate.Status.Condition = networkingv1alpha1.Failed
		r.Status().Update(ctx, &ingressTemplate)
		return ctrl.Result{}, err
	}
	log.Info("updated Ingress resource for IngressTemplate")
	ingressTemplate.Status.Condition = networkingv1alpha1.Created
	r.Status().Update(ctx, &ingressTemplate)
	return ctrl.Result{}, nil
}

/*
	func getSecretStatusforName(ingressTemplate *networkingv1alpha1.IngressTemplate, name string) networkingv1alpha1.ObjectStatus {
		var foundIndex int
		var foundStatus networkingv1alpha1.ObjectStatus
		for index, status := range ingressTemplate.Status.Secrets {
			if status.Name == name {
				foundIndex = index
				foundStatus = status
				break
			}
		}
		ingressTemplate.Status.Secrets = deleteElement(ingressTemplate.Status.Secrets, foundIndex)
		return foundStatus
	}

	func getConfigMapStatusforName(ingressTemplate *networkingv1alpha1.IngressTemplate, name string) networkingv1alpha1.ObjectStatus {
		var foundIndex int
		var foundStatus networkingv1alpha1.ObjectStatus
		for index, status := range ingressTemplate.Status.ConfigMaps {
			if status.Name == name {
				foundIndex = index
				foundStatus = status
				break
			}
		}
		ingressTemplate.Status.Secrets = deleteElement(ingressTemplate.Status.Secrets, foundIndex)
		return foundStatus
	}
*/
func deleteElement(slice []networkingv1alpha1.ObjectStatus, index int) []networkingv1alpha1.ObjectStatus {
	if len(slice) < 2 && index == 0 {
		return []networkingv1alpha1.ObjectStatus{}
	}
	return append(slice[:index], slice[index+1:]...)
}

func buildStatus(ingressTemplate *networkingv1alpha1.IngressTemplate) Statuses {
	statuses := Statuses{Secrets: make(map[string]networkingv1alpha1.ObjectStatus), ConfigMaps: make(map[string]networkingv1alpha1.ObjectStatus)}

	for _, replacement := range ingressTemplate.Spec.SecretReplacements {
		currentStatus, ok := statuses.Secrets[replacement.Name+"-"+replacement.Selector]
		if !ok {
			for _, secret := range ingressTemplate.Status.Secrets {
				if replacement.Name == secret.Name && replacement.Selector == secret.Selector {
					currentStatus = *secret.DeepCopy()
					break
				}
			}
			currentStatus = networkingv1alpha1.ObjectStatus{Name: replacement.Name, Selector: replacement.Selector, Status: networkingv1alpha1.NotFound}
			statuses.Secrets[replacement.Name+"-"+replacement.Selector] = currentStatus
		}
	}
	for _, replacement := range ingressTemplate.Spec.ConfigMapReplacements {
		currentStatus, ok := statuses.ConfigMaps[replacement.Name+"-"+replacement.Selector]
		if !ok {
			for _, configmap := range ingressTemplate.Status.ConfigMaps {
				if replacement.Name == configmap.Name && replacement.Selector == configmap.Selector {
					currentStatus = *configmap.DeepCopy()
					break
				}
			}
			currentStatus = networkingv1alpha1.ObjectStatus{Name: replacement.Name, Selector: replacement.Selector, Status: networkingv1alpha1.NotFound}
			statuses.ConfigMaps[replacement.Name+"-"+replacement.Selector] = currentStatus
		}
	}
	return statuses
}

func setResourcesStatus(ingressTemplate *networkingv1alpha1.IngressTemplate, statuses Statuses) {
	secretsStatuses := []networkingv1alpha1.ObjectStatus{}
	for _, value := range statuses.Secrets {
		secretsStatuses = append(secretsStatuses, value)
	}
	ingressTemplate.Status.Secrets = secretsStatuses
	configStatuses := []networkingv1alpha1.ObjectStatus{}
	for _, value := range statuses.ConfigMaps {
		configStatuses = append(configStatuses, value)
	}
	ingressTemplate.Status.ConfigMaps = configStatuses
}

func (r *IngressTemplateReconciler) findObjectForSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	attachedIngressTemplates := &networkingv1alpha1.IngressTemplateList{}
	listOps := &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(secretNameField, secret.GetName()),
		Namespace:     secret.GetNamespace(),
	}
	err := r.List(ctx, attachedIngressTemplates, listOps)
	if err != nil {
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, len(attachedIngressTemplates.Items))
	for i, item := range attachedIngressTemplates.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      item.GetName(),
				Namespace: item.GetNamespace(),
			},
		}
	}
	return requests
}

func (r *IngressTemplateReconciler) findObjectForConfigMap(ctx context.Context, configmap client.Object) []reconcile.Request {
	attachedIngressTemplates := &networkingv1alpha1.IngressTemplateList{}
	listOps := &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(configmapNameField, configmap.GetName()),
		Namespace:     configmap.GetNamespace(),
	}
	err := r.List(ctx, attachedIngressTemplates, listOps)
	if err != nil {
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, len(attachedIngressTemplates.Items))
	for i, item := range attachedIngressTemplates.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      item.GetName(),
				Namespace: item.GetNamespace(),
			},
		}
	}
	return requests
}

func (r *IngressTemplateReconciler) cleanupOwnedResources(ctx context.Context, ingressTemplate *networkingv1alpha1.IngressTemplate) error {
	log := log.FromContext(ctx)
	log.Info("finding existing Owned Resources for IngressTemplate resource")

	// List all deployment resources owned by this MyKind
	var ingressList networkingv1.IngressList
	if err := r.List(ctx, &ingressList, client.InNamespace(ingressTemplate.Namespace)); err != nil {
		return err
	}

	deleted := 0
	for _, ingress := range ingressList.Items {
		mine := false
		if len(ingress.OwnerReferences) > 0 {
			for _, reference := range ingress.OwnerReferences {
				mine = reference.Name == ingressTemplate.Namespace &&
					reference.Kind == ingressTemplate.Kind &&
					reference.APIVersion == ingressTemplate.APIVersion &&
					reference.UID == ingressTemplate.UID
			}

		}
		if !mine {
			continue
		}

		if err := r.Client.Delete(ctx, &ingress); err != nil {
			log.Error(err, "failed to delete Ingress resource")
			return err
		}
		r.Recorder.Eventf(ingressTemplate, corev1.EventTypeNormal, "Deleted", "Deleted Ingress %q", ingress.Name)
		deleted++
	}

	log.Info("finished cleaning up old Deployment resources", "number_deleted", deleted)

	return nil
}

func buildIngress(log *logr.Logger, ingressTemplate *networkingv1alpha1.IngressTemplate, replacements *[]Replacement) *networkingv1.Ingress {
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:            ingressTemplate.Name,
			Namespace:       ingressTemplate.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ingressTemplate, networkingv1alpha1.GroupVersion.WithKind("IngressTemplate"))},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ingressTemplate.Spec.IngressClassName,
			DefaultBackend:   ingressTemplate.Spec.DefaultBackend,
			TLS:              ingressTemplate.Spec.TLS,
		},
	}
	updateRules(log, &ingress, ingressTemplate, replacements)
	return &ingress
}

func updateRules(log *logr.Logger, ingress *networkingv1.Ingress, ingressTemplate *networkingv1alpha1.IngressTemplate, replacements *[]Replacement) {
	ingress.Spec.Rules = nil
	for _, rule := range ingressTemplate.Spec.Rules {
		fixedRule := networkingv1.IngressRule{
			IngressRuleValue: networkingv1.IngressRuleValue{
				HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{}}}}

		hostToFix := rule.Host
		for _, replacement := range *replacements {
			if strings.Contains(rule.Host, replacement.Selector) {
				if log != nil {
					log.Info(fmt.Sprintf("updateRule(Host): %q fixed with %q > %q ", rule.Host, replacement.Selector, replacement.Replacement))
				}
				hostToFix = strings.Replace(hostToFix, replacement.Selector, replacement.Replacement, -1)
			}
		}
		fixedRule.Host = hostToFix

		for _, path := range rule.HTTP.Paths {
			pathToFix := path.Path
			for _, replacement := range *replacements {
				if strings.Contains(pathToFix, replacement.Selector) {
					oldPath := pathToFix
					pathToFix = strings.Replace(pathToFix, replacement.Selector, replacement.Replacement, -1)
					if log != nil {
						log.Info(fmt.Sprintf("updateRule(Path): %q fixed with %q > %q to %q", oldPath, replacement.Selector, replacement.Replacement, pathToFix))
					}
				}
			}
			fixedPath := networkingv1.HTTPIngressPath{PathType: path.PathType, Backend: path.Backend, Path: pathToFix}
			fixedRule.HTTP.Paths = append(fixedRule.HTTP.Paths, fixedPath)
		}
		ingress.Spec.Rules = append(ingress.Spec.Rules, fixedRule)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressTemplateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &networkingv1alpha1.IngressTemplate{}, secretNameField, func(rawObj client.Object) []string {
		// Extract the ConfigMap name from the ConfigDeployment Spec, if one is provided
		ingressTemplate := rawObj.(*networkingv1alpha1.IngressTemplate)
		if ingressTemplate.Name == "" {
			return nil
		}
		return []string{ingressTemplate.Name}
	}); err != nil {
		return err
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &networkingv1alpha1.IngressTemplate{}, configmapNameField, func(rawObj client.Object) []string {
		// Extract the ConfigMap name from the ConfigDeployment Spec, if one is provided
		ingressTemplate := rawObj.(*networkingv1alpha1.IngressTemplate)
		if ingressTemplate.Name == "" {
			return nil
		}
		return []string{ingressTemplate.Name}
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha1.IngressTemplate{}).
		Owns(&networkingv1.Ingress{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findObjectForSecret),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.findObjectForConfigMap),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(r)
}
