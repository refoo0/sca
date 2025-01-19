### Install SCA Tools

```bash
brew install trivy
brew install osv-scanner
brew tap snyk/tap
brew install snyk
```

### Struktur dieses Repos

- **Ordner `app`:**

  - **`apps`:** Hier befinden sich die Anwendungen, die entwickelt wurden, um sie in den Testfällen zu nutzen. Die Namen der Anwendungen in der Arbeit sind wie folgt definiert:
    - `app1 = app-patched`
    - `app2 = app-unpatched`
    - `app3 = app-transitiv`

- **Ordner `projects`:**

  - Enthält die Open-Source-Projekte, die gescannt werden sollen.

- **Ordner `testAnwendungen`:**

  - Selbst entwickelte Testfälle, die mit den Anwendungen gescannt werden.

- **Ordner `testAnwendungen-AfterScan`:**

  - Da Snyk einige Dateien während des Scans überschreibt, enthält dieser Ordner die Testfälle nach dem Scan. Die ursprünglichen Testfälle befinden sich im Ordner `testAnwendungen`.

- **Ordner `results`:**

  - **`projects`:** Ergebnisse der Open-Source-Projekte. Die Ergebnisse sind nach Projekten aufgeteilt. Innerhalb jedes Projekts sind die Ergebnisse zusätzlich nach SCA-Tools unterteilt.
  - **`projectResults`:** Enthält die Ergebnisse aller drei Tools, normalisiert und zusammengefasst mit Hilfe eines selbst entwickelten Go-Programms.
  - **`results.json`:** Enthält die zusammengefassten Ergebnisse aller Tools und Projekte. Auch dieses wurde mit dem Go-Programm generiert.
  - **`testAnwendungen`:** Ergebnisse der Testfälle, aufgeteilt nach Testfällen und SCA-Tools.

- **Ordner `scan`:**

  - Enthält das selbst entwickelte Go-Programm, das die Ergebnisse analysiert und zusammenfasst.

- **Ordner `scripts`:**

  - Enthält die Skripte, um den Scan zu starten.

- **Makefile**

### Einen Scan starten

Die Skripte benötigen zwei Argumente: den Speicherpfad für die Ergebnisse und den Pfad, der gescannt werden soll.

- **OSV Scanner:**

  ```bash
  ./scripts/scanner/osv.sh save-path scan-path
  ```

- **Snyk:**

  ```bash
  ./scripts/scanner/snyk.sh save-path scan-path
  ```

- **Trivy:**

  ```bash
  ./scripts/scanner/trivy.sh save-path scan-path
  ```

- **Mit allen drei Tools scannen:**
  ```bash
  ./scripts/scan.sh save-path scan-path
  ```

### Ergebnisse analysieren

- Ergebnisse der drei Tools normalisieren

  **Argumente:**

  **SUBDIRS** sind die Verzeichnisse, in denen die Ergebnisse der Tools gespeichert sind. Die Ergebnisse der drei Tools werden für jedes Projekt normalisiert und zusammengefasst.

  ```bash
  @for subdir in $(SUBDIRS); do \
      echo "Running analysis for $$subdir"; \
      go run ./scan/main.go analysis \
          $(RESULT_DIR)/$$subdir/osv.json \
          $(RESULT_DIR)/$$subdir/trivy.json \
          $(RESULT_DIR)/$$subdir/snyk.json \
          $(RESULT_DIR)/$$subdir; \
      done
  ```

- Ergebnisse alle Tools analysieren und zusammenfasen

  **Argumente:**

  - Pfad zu den zusammengefassten Ergebnissen der drei Tools für jedes Projekt.
  - Speicherort für die Ergebnisse.

  Das Ergebnis ist eine JSON-Datei, die die analysierten Ergebnisse aller Projekte enthält.

  ```bash
  go run ./scan/main.go generate ./results/projects/projectResults output.json
  ```
