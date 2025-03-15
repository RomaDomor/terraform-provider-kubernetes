// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// https://kubernetes.github.io/ingress-nginx/deploy/#quick-start
// https://github.com/helm/helm/issues/11047

package kubernetes

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	networking "k8s.io/api/networking/v1"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
			Description: "The domain name associated with the API gateway. This should be a fully qualified domain name (FQDN)."
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
					"limit_connections": {
						Type:        schema.TypeInt,
						Optional:    true,
						Default:     50,
						Description: "The maximum number of concurrent connections allowed per IP address. Default is 50.",
						ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
							v := val.(int)
							if v < 1 {
								errs = append(errs, fmt.Errorf("%q must be at least 1, got %d", key, v))
							}
							return
						},
					},
					"limit_rps": {
						Type:        schema.TypeInt,
						Optional:    true,
						Description: "The rate limit for requests per second (RPS) for the service. Optional. Conflicts with 'limit_rpm'.",
						ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
							v := val.(int)
							if v <= 0 {
								errs = append(errs, fmt.Errorf("%q must be a positive integer, got %d", key, v))
							}
							return
						},
					},
					"limit_rpm": {
						Type:        schema.TypeInt,
						Optional:    true,
						Description: "The rate limit for requests per minute (RPM) for the service. Optional. Conflicts with 'limit_rps'.",
						ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
							v := val.(int)
							if v <= 0 {
								errs = append(errs, fmt.Errorf("%q must be a positive integer, got %d", key, v))
							}
							return
						},
					},
					"limit_burst_multiplier": {
						Type:        schema.TypeInt,
						Optional:    true,
						Default:     5,
						Description: "A multiplier that determines how much traffic can burst over the rate limit. Default is 5.",
						ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
							v := val.(int)
							if v <= 0 {
								errs = append(errs, fmt.Errorf("%q must be a positive integer, got %d", key, v))
							}
							return
						},
					},
					"upstream_max_fails": {
						Type:        schema.TypeInt,
						Optional:    true,
						Default:     3,
						Description: "The maximum number of upstream failures before considering the service unavailable. Default is 3.",
						ValidateFunc: func(val interface{}, key string) (warns []string, errs []error) {
							v := val.(int)
							if v < 1 {
								errs = append(errs, fmt.Errorf("%q must be at least 1, got %d", key, v))
							}
							return
						},
					},
					"upstream_fail_timeout": {
						Type:        schema.TypeString,
						Optional:    true,
						Default:     "30s",
						Description: "The duration to wait before retrying a failed upstream. Default is 30 seconds.",
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

func resourceKubernetesAPIGatewayV1Create(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn, err := meta.(KubeClientsets).MainClientset()
	if err != nil {
		return diag.FromErr(err)
	}

	// Extract values from Terraform schema
	namespace := d.Get("namespace").(string)
	name := d.Get("name").(string)
	domain := d.Get("domain").(string)
	authURL := d.Get("auth_url").(string)
	circuitBreaker := d.Get("circuit_breaker").([]interface{})

	// Define Ingress rules
	routes := d.Get("route").([]interface{})
	paths := createIngressRules(routes)

	// Define Annotations for Rate Limiting, Authentication, Custom Headers
	annotations, err := getAnnotations(authURL, circuitBreaker)
	if err != nil {
		return diag.FromErr(err)
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
	if annotations != nil {
		if rateLimit, ok := annotations["nginx.ingress.kubernetes.io/limit-rps"]; ok {
			err = d.Set("rate_limit", rateLimit)
			if err != nil {
				return diag.FromErr(err)
			}

		}
		if authURL, ok := annotations["nginx.ingress.kubernetes.io/auth-url"]; ok {
			err = d.Set("auth_url", authURL)
			if err != nil {
				return diag.FromErr(err)
			}

		}
		//if customHeader, ok := annotations["nginx.ingress.kubernetes.io/configuration-snippet"]; ok {
		//	err = d.Set("custom_header", customHeader)
		//	if err != nil {
		//		return diag.FromErr(err)
		//	}
		//}
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
	conn, err := meta.(KubeClientsets).MainClientset()
	if err != nil {
		return diag.FromErr(err)
	}

	namespace, name, err := idParts(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	domain := d.Get("domain").(string)
	authURL := d.Get("auth_url").(string)
	circuitBreaker := d.Get("circuit_breaker").([]interface{})

	// Define Ingress rules
	routes := d.Get("route").([]interface{})
	paths := createIngressRules(routes)

	// Define Annotations for Rate Limiting, Authentication, Custom Headers
	annotations, err := getAnnotations(authURL, circuitBreaker)
	if err != nil {
		return diag.FromErr(err)
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

func getAnnotations(authURL string, circuitBreaker []interface{}) (map[string]string, error) {
	annotations := map[string]string{
		"nginx.ingress.kubernetes.io/rewrite-target": "/$1",
	}

	if authURL != "" {
		annotations["nginx.ingress.kubernetes.io/auth-url"] = authURL
	}

	if len(circuitBreaker) > 0 {
		cb := circuitBreaker[0].(map[string]interface{})

		// Connection Limits
		if v, ok := cb["limit_connections"]; ok && v != 0 {
			annotations["nginx.ingress.kubernetes.io/limit-connections"] = fmt.Sprintf("%d", v.(int))
		}

		//_, hasRPS := cb["limit_rps"]
		//_, hasRPM := cb["limit_rpm"]
		//
		//if hasRPS && hasRPM {
		//	return nil, fmt.Errorf("cannot specify both 'limit_rps' and 'limit_rpm' at the same time")
		//}

		if v, ok := cb["limit_rps"]; ok && v != 0 {
			annotations["nginx.ingress.kubernetes.io/limit-rps"] = fmt.Sprintf("%d", v.(int))
		} else if v, ok := cb["limit_rpm"]; ok && v != 0 {
			annotations["nginx.ingress.kubernetes.io/limit-rpm"] = fmt.Sprintf("%d", v.(int))
		}

		// Burst Multiplier (used for rate limiting)
		if v, ok := cb["limit_burst_multiplier"]; ok && v != 0 {
			annotations["nginx.ingress.kubernetes.io/limit-burst-multiplier"] = fmt.Sprintf("%d", v.(int))
		}

		// Upstream Failure Handling
		if v, ok := cb["upstream_max_fails"]; ok && v != 0 {
			annotations["nginx.ingress.kubernetes.io/upstream-max-fails"] = fmt.Sprintf("%d", v.(int))
		}
		if v, ok := cb["upstream_fail_timeout"]; ok && v != 0 {
			annotations["nginx.ingress.kubernetes.io/upstream-fail-timeout"] = v.(string)
		}
	}

	return annotations, nil
}

func resourceKubernetesAPIGatewayV1Delete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn, err := meta.(KubeClientsets).MainClientset()
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
			IngressClassName: strPtr("nginx"),
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
