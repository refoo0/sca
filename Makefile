DIR = app
SUBDIR = caddy
APP_PATH = $(DIR)/$(SUBDIR)

run::
	./scripts/scan.sh $(APP_PATH)
	go run ./scan/main.go analysis ./results/scanner/osv.json ./results/scanner/trivy.json ./results/scanner/snyk.json $(SUBDIR) 

t::
	go run ./scan/main.go analysis ./results/scanner/osv.json ./results/scanner/trivy.json ./results/scanner/snyk.json $(SUBDIR) 
