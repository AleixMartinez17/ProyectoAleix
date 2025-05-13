document.addEventListener('DOMContentLoaded', function() {
    console.log("auth.js cargado correctamente");

    // Elementos del DOM
    const loginForm = document.getElementById('loginForm');
    const continueBtn = document.getElementById('continueBtn');
    const verifyBtn = document.getElementById('verifyBtn');
    const showQRBtn = document.getElementById('showQRBtn');
    const hideQRBtn = document.getElementById('hideQRBtn');

    // Verificar si ya está autenticado
    const userData = JSON.parse(localStorage.getItem('userData'));
    if (userData && userData.email && window.location.pathname.endsWith('login.html')) {
        window.location.href = 'index.html';
    }

    // Asignación de eventos
    if (continueBtn) {
        continueBtn.addEventListener('click', handleLoginSubmit);
    }

    if (verifyBtn) {
        verifyBtn.addEventListener('click', verifyMFA);
    }

    if (showQRBtn) {
        showQRBtn.addEventListener('click', showQR);
    }

    if (hideQRBtn) {
        hideQRBtn.addEventListener('click', hideQR);
    }

    // Funciones
    async function handleLoginSubmit() {
        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value.trim();
        const errorElement = document.getElementById("error-message");

        if (!email || !password) {
            showError("Por favor, completa todos los campos.");
            return;
        }

        try {
            toggleLoader("continueBtn", true);
            showMessage("Verificando credenciales...");

            const response = await fetch("http://localhost:3000/login-precheck", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Error en las credenciales');
            }

            document.getElementById("mfa-section").style.display = "block";
            showMessage("Introduce tu código MFA", true);
            
        } catch (err) {
            showError(err.message || "Error al verificar credenciales");
        } finally {
            toggleLoader("continueBtn", false);
        }
    }

    async function verifyMFA() {
        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value.trim();
        const mfaToken = document.getElementById("mfa").value.trim();

        if (!mfaToken || mfaToken.length !== 6) {
            showError("El código MFA debe tener 6 dígitos");
            return;
        }

        try {
            toggleLoader("verifyBtn", true);
            showMessage("Verificando código...");

            const response = await fetch("http://localhost:3000/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password, token: mfaToken })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || "Error en la autenticación");
            }

            localStorage.setItem('userData', JSON.stringify(data.user));
            window.location.href = "index.html";
            
        } catch (err) {
            showError(err.message || "Error al verificar el código");
        } finally {
            toggleLoader("verifyBtn", false);
        }
    }

    async function showQR() {
        const email = document.getElementById("email").value.trim();
        if (!email) {
            showError("Introduce tu email primero");
            return;
        }

        try {
            const response = await fetch(`http://localhost:3000/generate-new-qr?email=${encodeURIComponent(email)}`);
            const data = await response.json();

            if (!response.ok) throw new Error(data.message || 'Error generando QR');

            document.getElementById("qr-image").src = data.qrCodeDataURL;
            document.getElementById("qr-section").style.display = "block";
            
        } catch (err) {
            showError(err.message);
        }
    }

    function hideQR() {
        document.getElementById("qr-section").style.display = "none";
    }

    // Helpers
    function toggleLoader(buttonId, show) {
        const btn = document.getElementById(buttonId);
        if (show) {
            btn.innerHTML = `<span class="loader"></span> ${btn.textContent}`;
            btn.disabled = true;
        } else {
            btn.innerHTML = btn.textContent.replace(`<span class="loader"></span>`, '');
            btn.disabled = false;
        }
    }

    function showMessage(message, isSuccess = false) {
        const element = document.getElementById("error-message");
        element.textContent = message;
        element.style.color = isSuccess ? "#86efac" : "#f87171";
    }

    function showError(message) {
        showMessage(message, false);
    }
});

document.getElementById('registerBtn').addEventListener('click', async (e) => {
  e.preventDefault();
  
  // 1. Recoger datos del formulario
  const userData = {
    name: document.querySelector('input[type="text"]').value,    // Nombre Completo
    email: document.querySelector('input[type="email"]').value,  // Correo
    password: document.getElementById('password').value
  };

  try {
    // 2. Enviar al backend
    const response = await fetch('http://localhost:3000/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData)
    });

    const result = await response.json();

    // 3. Manejar errores
    if (!response.ok) {
      const errorMessages = result.errors 
        ? Object.values(result.errors).flat() 
        : [result.message || "Error desconocido"];
      
      document.getElementById('error-message').innerHTML = `
        <div style="color: red;">
          ${errorMessages.map(msg => `❌ ${msg}`).join('<br>')}
        </div>
      `;
      return;
    }

    // 4. Éxito: Mostrar QR
    document.querySelector('.login-container').style.display = 'none';
    document.getElementById('qr-section').style.display = 'block';
    document.getElementById('qr-image').src = result.qrCodeDataURL;
    document.getElementById('background').textContent = result.backupCodes.join(' ');

  } catch (error) {
    document.getElementById('error-message').innerHTML = `
      <div style="color: red;">Error de conexión con el servidor</div>
    `;
    console.error("Error:", error);
  }
});

        document.getElementById('togglePassword').addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            const eyeIcon = document.getElementById('eyeIcon');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                eyeIcon.textContent = '🙈';
            } else {
                passwordInput.type = 'password';
                eyeIcon.textContent = '👁️';
            }
        });