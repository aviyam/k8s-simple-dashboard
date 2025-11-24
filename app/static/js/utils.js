// search functionality for resource table
const searchInput = document.getElementById('globalSearchInput');
if (searchInput) {
    searchInput.addEventListener('input', function () {
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

// Theme Switcher Logic
const toggleSwitch = document.getElementById('checkbox');
const currentTheme = localStorage.getItem('theme');

if (currentTheme) {
    document.documentElement.setAttribute('data-theme', currentTheme);
    if (currentTheme === 'dark') {
        if (toggleSwitch) toggleSwitch.checked = true;
    }
} else {
    // Default to dark theme
    document.documentElement.setAttribute('data-theme', 'dark');
    if (toggleSwitch) toggleSwitch.checked = true;
}

function switchTheme(e) {
    if (e.target.checked) {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
    } else {
        document.documentElement.setAttribute('data-theme', 'light');
        localStorage.setItem('theme', 'light');
    }
}

if (toggleSwitch) {
    toggleSwitch.addEventListener('change', switchTheme, false);
}