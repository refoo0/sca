package main

import (
	"context"
	"fmt"
	"log"

	argo "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	wfclientset "github.com/argoproj/argo-workflows/v3/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func main() {

	// Erstelle die Konfiguration
	client, err := wfclientset.NewForConfig(&rest.Config{
		Host: "https://argo-server-url",
	})
	if err != nil {
		log.Fatalf("Fehler beim Erstellen der Workflow-Client: %v", err)
	}

	workflow := &argo.Workflow{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "example-workflow-",
			Namespace:    "default",
		},
		Spec: argo.WorkflowSpec{
			Entrypoint: "whalesay",
			Templates: []argo.Template{
				{
					Name: "whalesay",
					Container: &corev1.Container{
						Image:   "docker/whalesay:latest",
						Command: []string{"cowsay"},
						Args:    []string{"hello world"},
					},
				},
			},
		},
	}

	createdWorkflow, err := client.ArgoprojV1alpha1().Workflows("default").Create(context.TODO(), workflow, metav1.CreateOptions{})
	if err != nil {
		log.Fatalf("Fehler beim Erstellen des Workflows: %v", err)
	}

	fmt.Printf("Workflow erstellt: %s\n", createdWorkflow.Name)

}
