import matplotlib.pyplot as plt
from matplotlib_venn import venn3
from matplotlib.patches import Patch

# Daten für das Venn-Diagramm
counts = {

    "OnlyOSV": 313,
    "OnlySnyk": 35,
    "OnlyTrivy": 5,
    "OSV_Snyk": 2,
    "OSV_Trivy": 30,
    "Snyk_Trivy": 3,
    "All": 103
}

# Erstellen des Venn-Diagramms mit Pastellfarben und voller Deckkraft
venn = venn3(
    subsets=(
        counts["OnlyOSV"],      # Nur OSV
        counts["OnlySnyk"],     # Nur Snyk
        counts["OSV_Snyk"],     # OSV und Snyk
        counts["OnlyTrivy"],    # Nur Trivy
        counts["OSV_Trivy"],    # OSV und Trivy
        counts["Snyk_Trivy"],   # Snyk und Trivy
        counts["All"]           # OSV, Snyk und Trivy
    ),
    set_labels=('OSV', 'Snyk', 'Trivy'),
    set_colors=('#FF9999', '#66B3FF', '#99FF99'),  # Pastellrot, Pastellblau, Pastellgrün
    alpha=.8  # Alpha-Wert auf 0.8 setzen, um die Farben leuchtender zu machen
)

# Entfernen der Zahlen innerhalb der Diagrammbereiche
for subset in venn.subset_labels:
    if subset:  # Überprüfen, ob das Label vorhanden ist
        subset.set_visible(False)

# Entfernen der Kreisbeschriftungen (A, B, C)
for label in venn.set_labels:
    label.set_visible(False)

# Anzeige des Venn-Diagramms
plt.title("Venn-Diagramm von OSV, Snyk und Trivy")

# Erstellen der benutzerdefinierten Legende mit passenden Farben
legend_patches = [
    Patch(color='#FF9999', label='OSV'),   # Pastellrot
    Patch(color='#66B3FF', label='Snyk'),  # Pastellblau
    Patch(color='#99FF99', label='Trivy')  # Pastellgrün
]
plt.legend(handles=legend_patches, loc='lower right')

plt.show()
