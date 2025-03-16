// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubernetes

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	networking "k8s.io/api/networking/v1"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntimeSchema "k8s.io/apimachinery/pkg/runtime/schema"
)

// TODO: General cleanup

// Define the GroupVersionResource for Traefik Middleware CRD.
var traefikMiddlewareGVR = k8sRuntimeSchema.GroupVersionResource{
	Group:    "traefik.io",
	Version:  "v1alpha1",
	Resource: "middlewares",
}

func resourceKubernetesAPIGatewayV1() *schema.Resource {
	return &schema.Resource{
		Description:   "A Service is an abstraction which defines a logical set of pods and a policy by which to access them - sometimes called a micro-service.",
		CreateContext: resourceKubernetesAPIGatewayV1Create,
		ReadContext:   resourceKubernetesAPIGatewayV1Read,
		UpdateContext: resourceKubernetesAPIGatewayV1Update,
		DeleteContext: resourceKubernetesAPIGatewayV1Delete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
		},
		SchemaVersion: 1,
		Schema:        resourceKubernetesAPIGatewaySchemaV1(),
	}
}

func resourceKubernetesAPIGatewaySchemaV1() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"namespace": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "default",
			Description: "The Kubernetes namespace where the API gateway should be deployed. Defaults to 'default'.",
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The name of the API gateway. This must be a unique identifier within the namespace.",
		},
		"domain": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The domain name associated with the API gateway. This should be a fully qualified domain name (FQDN).",
		},
		"route": {
			Type:     schema.TypeList,
			Required: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"path": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "The path pattern that will be used for routing requests to the corresponding service. E.g., '/service1'.",
					},
					"service_name": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "The name of the Kubernetes service that the route will forward requests to.",
					},
					"service_port": {
						Type:        schema.TypeInt,
						Required:    true,
						Description: "The port on the service where the API gateway will route traffic. Typically, this is the port the service is listening on.",
					},
				},
			},
			Description: "List of routes, each specifying a path, service name, and service port. Defines how requests to specific paths are routed to services.",
		},
		"circuit_breaker": {
			Type:     schema.TypeList,
			Optional: true,
			MaxItems: 1,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"metric": {
						Type:         schema.TypeString,
						Optional:     true,
						Default:      "latency",
						Description:  "The metric type used to trigger the circuit breaker. Valid options are 'latency', 'network_error', or 'response_code'.",
						ValidateFunc: validation.StringInSlice([]string{"latency", "network_error", "response_code"}, false),
					},
					"latency_quantile": {
						Type:     schema.TypeFloat,
						Optional: true,
						//Default:     50.0,
						Description: "For the latency metric: the quantile to evaluate (e.g., 50.0 for the median). Must be between 0 and 100.",
						ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
							v := val.(float64)
							if v <= 0 || v > 100 {
								errs = append(errs, fmt.Errorf("%q must be > 0 and <= 100, got %v", key, v))
							}
							return
						},
					},
					"latency_threshold": {
						Type:     schema.TypeInt,
						Optional: true,
						//Default:      100,
						Description:  "For the latency metric: the threshold in milliseconds above which the circuit breaker will open.",
						ValidateFunc: validation.IntAtLeast(1),
					},
					"network_error_threshold": {
						Type:     schema.TypeFloat,
						Optional: true,
						//Default:     0.30,
						Description: "For the network error metric: the error ratio threshold. Must be between 0 and 1.",
						ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
							v := val.(float64)
							if v < 0 || v > 1 {
								errs = append(errs, fmt.Errorf("%q must be between 0 and 1, got %v", key, v))
							}
							return
						},
					},
					"response_code_from": {
						Type:     schema.TypeInt,
						Optional: true,
						//Default:      500,
						Description:  "For the response code metric: the starting HTTP status code (inclusive) for evaluation. Must be between 100 and 599.",
						ValidateFunc: validation.IntBetween(100, 599),
					},
					"response_code_to": {
						Type:     schema.TypeInt,
						Optional: true,
						//Default:      600,
						Description:  "For the response code metric: the ending HTTP status code (exclusive) for evaluation. Must be between 101 and 600.",
						ValidateFunc: validation.IntBetween(101, 600),
					},
					"divided_by_from": {
						Type:     schema.TypeInt,
						Optional: true,
						//Default:      0,
						Description:  "For the response code metric: the starting HTTP status code (inclusive) of the denominator range. Must be >= 0.",
						ValidateFunc: validation.IntAtLeast(0),
					},
					"divided_by_to": {
						Type:     schema.TypeInt,
						Optional: true,
						//Default:      600,
						Description:  "For the response code metric: the ending HTTP status code (exclusive) of the denominator range. Must be between 1 and 600.",
						ValidateFunc: validation.IntBetween(1, 600),
					},
					"response_code_threshold": {
						Type:     schema.TypeFloat,
						Optional: true,
						//Default:     0.25,
						Description: "For the response code metric: the ratio threshold above which the circuit breaker will open. Must be between 0 and 1.",
						ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
							v := val.(float64)
							if v < 0 || v > 1 {
								errs = append(errs, fmt.Errorf("%q must be between 0 and 1, got %v", key, v))
							}
							return
						},
					},
					"check_period": {
						Type:         schema.TypeString,
						Optional:     true,
						Default:      "100ms",
						Description:  "The interval between successive checks of the circuit breaker condition. Must be a valid duration (e.g., '100ms', '1s').",
						ValidateFunc: validateDurationString,
					},
					"fallback_duration": {
						Type:         schema.TypeString,
						Optional:     true,
						Default:      "10s",
						Description:  "The duration for which the circuit breaker remains open before attempting recovery. Must be a valid duration (e.g., '10s').",
						ValidateFunc: validateDurationString,
					},
					"recovery_duration": {
						Type:         schema.TypeString,
						Optional:     true,
						Default:      "10s",
						Description:  "The duration for which the circuit breaker remains in a recovering state. Must be a valid duration (e.g., '10s').",
						ValidateFunc: validateDurationString,
					},
					"response_code": {
						Type:         schema.TypeInt,
						Optional:     true,
						Default:      503,
						Description:  "The HTTP status code returned when the circuit breaker is open. Must be between 100 and 599.",
						ValidateFunc: validation.IntBetween(100, 599),
					},
				},
			},
			Description: "Configuration for the circuit breaker, including rate limits, burst handling, and failure handling for upstream services.",
		},
		"auth_url": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Optional URL for authentication service, to ensure that all incoming requests are authenticated before reaching the backend services.",
		},
		"status": {
			Type:     schema.TypeList,
			Computed: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"load_balancer": {
						Type:     schema.TypeList,
						Computed: true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"ingress": {
									Type:     schema.TypeList,
									Computed: true,
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											"ip": {
												Type:        schema.TypeString,
												Computed:    true,
												Description: "The IP address of the load balancer for the API gateway.",
											},
											"hostname": {
												Type:        schema.TypeString,
												Computed:    true,
												Description: "The hostname of the load balancer for the API gateway.",
											},
										},
									},
									Description: "Ingress details for the load balancer, including the IP address and hostname.",
								},
							},
						},
					},
				},
			},
			Description: "Computed status of the API gateway, including load balancer ingress information.",
		},
	}
}

// validateDurationString validates that the provided string is a valid duration.
func validateDurationString(val interface{}, key string) (warns []string, errs []error) {
	s, ok := val.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("%q must be a string, got: %T", key, val))
		return
	}
	if _, err := time.ParseDuration(s); err != nil {
		errs = append(errs, fmt.Errorf("%q must be a valid duration string (e.g., '100ms', '10s'), got: %s", key, s))
	}
	return
}

func resourceKubernetesAPIGatewayV1Create(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// Get the main Kubernetes client (for Ingress objects)
	conn, err := meta.(KubeClientsets).MainClientset()
	if err != nil {
		return diag.FromErr(err)
	}

	// Get the dynamic client for creating CRDs (like Traefik Middleware)
	dynClient, err := meta.(KubeClientsets).DynamicClient()
	if err != nil {
		return diag.FromErr(err)
	}

	// Extract values from the Terraform schema
	namespace := d.Get("namespace").(string)
	name := d.Get("name").(string)
	domain := d.Get("domain").(string)

	// Define Ingress rules
	routes := d.Get("route").([]interface{})
	paths := createIngressRules(routes)

	// Prepare annotations
	annotations := map[string]string{}

	// Deploy Circuit Breaker if required
	circuitBreaker := d.Get("circuit_breaker").([]interface{})
	if len(circuitBreaker) > 0 {
		// Create Traefik middleware for circuit breaking.
		obj := getCircuitBreakerObject(namespace, name, circuitBreaker)
		_, err := dynClient.Resource(traefikMiddlewareGVR).Namespace(namespace).Create(ctx, obj, metav1.CreateOptions{})
		if err != nil {
			return diag.Errorf("Failed to update Traefik middleware: %s", err)
		}

		// Reference the middleware in the Ingress via annotation.
		// Traefik expects: traefik.ingress.kubernetes.io/router.middlewares: "namespace/middleware-name"
		annotations["traefik.ingress.kubernetes.io/router.middlewares"] = fmt.Sprintf("%s-%s-circuit-breaker@kubernetescrd", namespace, name)
	}

	// Create Ingress object
	ingress := getIngressObject(namespace, name, annotations, domain, paths)

	// Apply Ingress
	log.Printf("[INFO] Creating new API Gateway ingress: %#v", ingress)
	out, err := conn.NetworkingV1().Ingresses(namespace).Create(ctx, ingress, metav1.CreateOptions{})
	if err != nil {
		return diag.Errorf("Failed to create API Gateway Ingress '%s' because: %s", buildId(ingress.ObjectMeta), err)
	}
	log.Printf("[INFO] Submitted new API Gateway ingress: %#v", out)
	d.SetId(buildId(out.ObjectMeta))

	return resourceKubernetesAPIGatewayV1Read(ctx, d, meta)
}

// getCircuitBreakerObject creates a Traefik Middleware CRD object for circuit breaking.
func getCircuitBreakerObject(namespace, gatewayName string, circuitBreaker []interface{}) *unstructured.Unstructured {
	cb := circuitBreaker[0].(map[string]interface{})

	// Determine the metric type. Default is "latency".
	metric := "latency"
	if v, ok := cb["metric"]; ok {
		if m, ok2 := v.(string); ok2 && m != "" {
			metric = m
		}
	}

	var expression string
	switch metric {
	case "latency":
		quantile := 50.0
		if v, ok := cb["latency_quantile"]; ok && v != "" {
			if q, ok2 := v.(float64); ok2 && q > 0 {
				quantile = q
			}
		}
		threshold := 100
		if v, ok := cb["latency_threshold"]; ok && v != "" {
			if t, ok2 := v.(int); ok2 && t > 0 {
				threshold = t
			}
		}
		expression = fmt.Sprintf("LatencyAtQuantileMS(%.1f) > %d", quantile, threshold)
	case "network_error":
		errorThreshold := 0.30
		if v, ok := cb["network_error_threshold"]; ok && v != "" {
			if et, ok2 := v.(float64); ok2 && et > 0 {
				errorThreshold = et
			}
		}
		expression = fmt.Sprintf("NetworkErrorRatio() > %.2f", errorThreshold)
	case "response_code":
		from := 500
		if v, ok := cb["response_code_from"]; ok && v != "" {
			if f, ok2 := v.(int); ok2 {
				from = f
			}
		}
		to := 600
		if v, ok := cb["response_code_to"]; ok && v != "" {
			if t, ok2 := v.(int); ok2 {
				to = t
			}
		}
		dividedByFrom := 0
		if v, ok := cb["divided_by_from"]; ok && v != "" {
			if df, ok2 := v.(int); ok2 {
				dividedByFrom = df
			}
		}
		dividedByTo := 600
		if v, ok := cb["divided_by_to"]; ok && v != "" {
			if dt, ok2 := v.(int); ok2 {
				dividedByTo = dt
			}
		}
		rcThreshold := 0.25
		if v, ok := cb["response_code_threshold"]; ok && v != "" {
			if rct, ok2 := v.(float64); ok2 {
				rcThreshold = rct
			}
		}
		expression = fmt.Sprintf("ResponseCodeRatio(%d, %d, %d, %d) > %.2f", from, to, dividedByFrom, dividedByTo, rcThreshold)
	default:
		// Fallback to latency if an unknown metric is provided.
		expression = "LatencyAtQuantileMS(50.0) > 100"
	}

	// Additional generic options.
	checkPeriod := "100ms"
	if v, ok := cb["check_period"]; ok && v != "" {
		if cp, ok2 := v.(string); ok2 && cp != "" {
			checkPeriod = cp
		}
	}
	fallbackDuration := "10s"
	if v, ok := cb["fallback_duration"]; ok && v != "" {
		if fd, ok2 := v.(string); ok2 && fd != "" {
			fallbackDuration = fd
		}
	}
	recoveryDuration := "10s"
	if v, ok := cb["recovery_duration"]; ok && v != "" {
		if rd, ok2 := v.(string); ok2 && rd != "" {
			recoveryDuration = rd
		}
	}
	responseCode := 503
	if v, ok := cb["response_code"]; ok && v != "" {
		if rc, ok2 := v.(int); ok2 && rc != 0 {
			responseCode = rc
		}
	}

	middleware := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "traefik.io/v1alpha1",
			"kind":       "Middleware",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("%s-circuit-breaker", gatewayName),
				"namespace": namespace,
				"labels": map[string]interface{}{
					"api-gateway": gatewayName,
				},
			},
			"spec": map[string]interface{}{
				"circuitBreaker": map[string]interface{}{
					"expression":       expression,
					"checkPeriod":      checkPeriod,
					"fallbackDuration": fallbackDuration,
					"recoveryDuration": recoveryDuration,
					"responseCode":     responseCode,
				},
			},
		},
	}

	return middleware
}

func resourceKubernetesAPIGatewayV1Read(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	exists, err := resourceKubernetesAPIGatewayV1Exists(ctx, d, meta)
	if err != nil {
		return diag.FromErr(err)
	}
	if !exists {
		d.SetId("")
		return diag.Diagnostics{}
	}

	conn, err := meta.(KubeClientsets).MainClientset()
	if err != nil {
		return diag.FromErr(err)
	}

	// Get the dynamic client for reading CRDs (like Traefik Middleware)
	dynClient, err := meta.(KubeClientsets).DynamicClient()
	if err != nil {
		return diag.FromErr(err)
	}

	namespace, name, err := idParts(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[INFO] Reading API Gateway %s", name)
	ing, err := conn.NetworkingV1().Ingresses(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		log.Printf("[DEBUG] Received error: %#v", err)
		return diag.Errorf("Failed to read API Gateway '%s': %s", buildId(ing.ObjectMeta), err)
	}

	log.Printf("[INFO] Received API Gateway: %#v", ing)

	// Set the basic metadata
	err = d.Set("domain", ing.Spec.Rules[0].Host) // Assuming there's only one rule
	if err != nil {
		return diag.FromErr(err)
	}
	// You can handle multiple rules or paths based on your use case

	// Set annotations if present
	annotations := ing.Annotations
	if mw, ok := annotations["traefik.ingress.kubernetes.io/router.middlewares"]; ok {
		if strings.Contains(mw, "circuit-breaker") {
			// The middleware reference contains "circuit-breaker"
			fmt.Printf("[INFO] Circuit breaker middleware reference found in annotation: %s", mw)
			// Expecting annotation value format: "<middlewareRef>@kubernetescrd"
			parts := strings.Split(mw, "@")
			if len(parts) < 1 {
				log.Printf("[DEBUG] Invalid middleware annotation format: %s", mw)
			} else {
				mwName, _ := strings.CutPrefix(parts[0], fmt.Sprintf("%s-", namespace))
				// Use the dynamic client to retrieve the middleware object.
				middlewareObj, err := dynClient.Resource(traefikMiddlewareGVR).Namespace(namespace).Get(ctx, mwName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						log.Printf("[DEBUG] Circuit breaker middleware %q not found", mwName)
					} else {
						return diag.Errorf("Failed to read circuit breaker middleware %q: %s", mwName, err)
					}
				} else {
					// Parse the circuit breaker configuration from the middleware spec.
					spec, found, err := unstructured.NestedMap(middlewareObj.Object, "spec", "circuitBreaker")
					if err != nil || !found {
						log.Printf("[DEBUG] Circuit breaker spec not found in middleware %q", mwName)
					} else {
						expression, _, _ := unstructured.NestedString(spec, "expression")
						checkPeriod, _, _ := unstructured.NestedString(spec, "checkPeriod")
						fallbackDuration, _, _ := unstructured.NestedString(spec, "fallbackDuration")
						recoveryDuration, _, _ := unstructured.NestedString(spec, "recoveryDuration")
						responseCode, _, _ := unstructured.NestedInt64(spec, "responseCode")
						// Build a map representing the circuit breaker configuration.
						cbMap := map[string]interface{}{
							//"expression":        expression,
							"check_period":      checkPeriod,
							"fallback_duration": fallbackDuration,
							"recovery_duration": recoveryDuration,
							"response_code":     int(responseCode),
						}
						// Reverse-engineer the generic metric settings from the computed expression.
						if strings.HasPrefix(expression, "LatencyAtQuantileMS(") {
							var quantile float64
							var threshold int
							n, err := fmt.Sscanf(expression, "LatencyAtQuantileMS(%f) > %d", &quantile, &threshold)
							if err == nil && n == 2 {
								cbMap["metric"] = "latency"
								cbMap["latency_quantile"] = quantile
								cbMap["latency_threshold"] = threshold
							}
						} else if strings.HasPrefix(expression, "NetworkErrorRatio() >") {
							var errorThreshold float64
							n, err := fmt.Sscanf(expression, "NetworkErrorRatio() > %f", &errorThreshold)
							if err == nil && n == 1 {
								cbMap["metric"] = "network_error"
								cbMap["network_error_threshold"] = errorThreshold
							}
						} else if strings.HasPrefix(expression, "ResponseCodeRatio(") {
							var from, to, dividedByFrom, dividedByTo int
							var rcThreshold float64
							n, err := fmt.Sscanf(expression, "ResponseCodeRatio(%d, %d, %d, %d) > %f", &from, &to, &dividedByFrom, &dividedByTo, &rcThreshold)
							if err == nil && n == 5 {
								cbMap["metric"] = "response_code"
								cbMap["response_code_from"] = from
								cbMap["response_code_to"] = to
								cbMap["divided_by_from"] = dividedByFrom
								cbMap["divided_by_to"] = dividedByTo
								cbMap["response_code_threshold"] = rcThreshold
							}
						}
						// Set the "circuit_breaker" block in state (as a list with one map).
						if err := d.Set("circuit_breaker", []interface{}{cbMap}); err != nil {
							return diag.FromErr(err)
						}
					}
				}
			}
		}
	}

	// Set the routes (paths) from the Ingress resource
	var routes []map[string]interface{}
	for _, rule := range ing.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			route := map[string]interface{}{
				"path":         path.Path,
				"service_name": path.Backend.Service.Name,
				"service_port": path.Backend.Service.Port.Number,
			}
			routes = append(routes, route)
		}
	}
	err = d.Set("route", routes)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set status (Load Balancer IP/Hostname)
	err = d.Set("status", []interface{}{
		map[string][]interface{}{
			"load_balancer": flattenIngressV1Status(ing.Status.LoadBalancer),
		},
	})
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceKubernetesAPIGatewayV1Update(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// Get the main Kubernetes client (for Ingress objects)
	conn, err := meta.(KubeClientsets).MainClientset()
	if err != nil {
		return diag.FromErr(err)
	}

	// Get the dynamic client for creating CRDs (like Traefik Middleware)
	dynClient, err := meta.(KubeClientsets).DynamicClient()
	if err != nil {
		return diag.FromErr(err)
	}

	namespace, name, err := idParts(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	// Extract values from the Terraform schema
	domain := d.Get("domain").(string)

	// Define Ingress rules
	routes := d.Get("route").([]interface{})
	paths := createIngressRules(routes)

	// Prepare annotations
	annotations := map[string]string{}

	// TODO: Delete existing Circuit Breaker if existed but removed
	// Redeploy Circuit Breaker if required
	circuitBreaker := d.Get("circuit_breaker").([]interface{})
	if len(circuitBreaker) > 0 {
		// Update Traefik middleware for circuit breaking.
		obj := getCircuitBreakerObject(namespace, name, circuitBreaker)
		_, err := dynClient.Resource(traefikMiddlewareGVR).Namespace(namespace).Update(ctx, obj, metav1.UpdateOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				_, err := dynClient.Resource(traefikMiddlewareGVR).Namespace(namespace).Create(ctx, obj, metav1.CreateOptions{})
				if err != nil {
					return diag.Errorf("Failed to create Circuit Breaker: %s", err)
				}
			} else {
				return diag.Errorf("Failed to update Circuit Breaker: %s", err)
			}
		}

		// Reference the middleware in the Ingress via annotation.
		// Traefik expects: traefik.ingress.kubernetes.io/router.middlewares: "namespace/middleware-name"
		annotations["traefik.ingress.kubernetes.io/router.middlewares"] = fmt.Sprintf("%s-%s-circuit-breaker@kubernetescrd", namespace, name)
	}

	ingress := getIngressObject(namespace, name, annotations, domain, paths)

	// Update the API Gateway resource
	updatedGateway, err := conn.NetworkingV1().Ingresses(namespace).Update(ctx, ingress, metav1.UpdateOptions{})
	if err != nil {
		return diag.Errorf("Failed to update API Gateway '%s' because: %s", buildId(ingress.ObjectMeta), err)
	}

	log.Printf("[INFO] Updated API Gateway: %#v", updatedGateway)
	return resourceKubernetesAPIGatewayV1Read(ctx, d, meta)
}

func resourceKubernetesAPIGatewayV1Delete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn, err := meta.(KubeClientsets).MainClientset()
	if err != nil {
		return diag.FromErr(err)
	}

	// Get the dynamic client for creating CRDs (like Traefik Middleware)
	dynClient, err := meta.(KubeClientsets).DynamicClient()
	if err != nil {
		return diag.FromErr(err)
	}

	namespace, name, err := idParts(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[INFO] Deleting API Gateway: %s", name)

	// Delete the Ingress
	err = conn.NetworkingV1().Ingresses(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return diag.Errorf("Failed to delete API Gateway %s because: %s", d.Id(), err)
	}

	// Wait for the resource to be fully removed
	err = retry.RetryContext(ctx, d.Timeout(schema.TimeoutDelete), func() *retry.RetryError {
		_, err := conn.NetworkingV1().Ingresses(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if statusErr, ok := err.(*errors.StatusError); ok && errors.IsNotFound(statusErr) {
				return nil
			}
			return retry.NonRetryableError(err)
		}

		e := fmt.Errorf("API Gateway (%s) still exists", d.Id())
		return retry.RetryableError(e)
	})
	if err != nil {
		return diag.FromErr(err)
	}

	// Delete middleware
	middlewareName := fmt.Sprintf("%s-circuit-breaker", name)
	err = dynClient.Resource(traefikMiddlewareGVR).Namespace(namespace).Delete(ctx, middlewareName, metav1.DeleteOptions{})
	if err != nil {
		// If the resource is not found, consider it already deleted.
		if errors.IsNotFound(err) {
			return nil
		}
		return diag.Errorf("failed to delete middleware %q: %s", middlewareName, err)
	}

	log.Printf("[INFO] API Gateway %s deleted", name)

	d.SetId("")
	return nil
}

func resourceKubernetesAPIGatewayV1Exists(ctx context.Context, d *schema.ResourceData, meta interface{}) (bool, error) {
	conn, err := meta.(KubeClientsets).MainClientset()
	if err != nil {
		return false, err
	}

	namespace, name, err := idParts(d.Id())
	if err != nil {
		return false, err
	}

	log.Printf("[INFO] Checking API Gateway %s", name)
	_, err = conn.NetworkingV1().Ingresses(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if statusErr, ok := err.(*errors.StatusError); ok && errors.IsNotFound(statusErr) {
			return false, nil
		}
		log.Printf("[DEBUG] Received error: %#v", err)
	}
	return true, err
}

func createIngressRules(routes []interface{}) []networking.HTTPIngressPath {
	var paths []networking.HTTPIngressPath
	for _, route := range routes {
		routeMap := route.(map[string]interface{})
		path := routeMap["path"].(string)
		serviceName := routeMap["service_name"].(string)
		servicePort := int32(routeMap["service_port"].(int))

		paths = append(paths, networking.HTTPIngressPath{
			Path:     path,
			PathType: &[]networking.PathType{networking.PathTypePrefix}[0],
			Backend: networking.IngressBackend{
				Service: &networking.IngressServiceBackend{
					Name: serviceName,
					Port: networking.ServiceBackendPort{
						Number: servicePort,
					},
				},
			},
		})
	}
	return paths
}

func getIngressObject(namespace, name string, annotations map[string]string, domain string, paths []networking.HTTPIngressPath) *networking.Ingress {
	return &networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Spec: networking.IngressSpec{
			IngressClassName: strPtr("traefik"),
			Rules: []networking.IngressRule{
				{
					Host: domain,
					IngressRuleValue: networking.IngressRuleValue{
						HTTP: &networking.HTTPIngressRuleValue{
							Paths: paths,
						},
					},
				},
			},
		},
	}
}

// Helper function to return a pointer to a string
func strPtr(s string) *string {
	return &s
}
