// search functionality for resource table
const searchInput = document.getElementById('globalSearchInput');
    console.log("Test")
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const tableBody = document.getElementById('resourceTableBody');
            if (tableBody) {
                const filter = this.value.toLowerCase();
                const rows = tableBody.getElementsByTagName('tr');
                for (const row of rows) {
                    const rowText = row.textContent || row.innerText;
                    if (rowText.toLowerCase().indexOf(filter) > -1) {
                        row.style.display = "";
                    } else {
                        row.style.display = "none";
                    }
                }
            }
        });
    }