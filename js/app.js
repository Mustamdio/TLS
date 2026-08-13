// Fonctions utilitaires globales
function showAlert(elementId, message) {
    const alert = document.getElementById(elementId);
    alert.textContent = message;
    alert.classList.add('show');
    setTimeout(() => alert.classList.remove('show'), 5000);
}

// Vérification de session
document.addEventListener('DOMContentLoaded', () => {
    // Si on est sur une page protégée (dashboard) et pas de token, rediriger
    const protectedPages = ['dashboard.html'];
    const currentPage = window.location.pathname.split('/').pop();
    
    if (protectedPages.includes(currentPage)) {
        const token = localStorage.getItem('token');
        if (!token) {
            window.location.href = 'index.html';
        }
    }
});
