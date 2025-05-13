document.addEventListener('DOMContentLoaded', function () {
  // Banner de animação
  const banner1 = document.getElementById('banner1');
  const banner2 = document.getElementById('banner2');
  const banner3 = document.getElementById('banner3');

  banner1.classList.add('active');

  // Banner 1: duração de 6 segundos
  setTimeout(() => {
    banner1.classList.remove('active');
    banner2.classList.add('active', 'fade-in');
  }, 6000);

  // Banner 2: duração de 4 segundos
  setTimeout(() => {
    banner2.classList.remove('active');
    banner3.classList.add('active', 'fade-in');
  }, 9000);

  // Navegação entre Steps
  window.nextStep = function() {
    document.getElementById('step1-content').classList.remove('active');
    document.getElementById('step2-content').classList.add('active');
  };

  window.prevStep = function() {
    document.getElementById('step2-content').classList.remove('active');
    document.getElementById('step1-content').classList.add('active');
  };

  // Função para mostrar notificações estilo Google
  function showToast(message, isSuccess = true) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = 'toast ' + (isSuccess ? 'success' : 'error');
    toast.classList.add('show');
    
    setTimeout(() => {
      toast.classList.remove('show');
    }, 3000);
  }

  // Função para copiar chaves
  window.copyToClipboard = function(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text)
      .then(() => showToast("Chave copiada com sucesso!"))
      .catch(() => showToast("Erro ao copiar chave.", false));
  };

  // Inicialização do WebAssembly
  Module.onRuntimeInitialized = function() {
    console.log("WebAssembly pronto!");
    
    // Gerar chave pública
    window.generateKey = function() {
      const p = document.getElementById('prime1').value;
      const q = document.getElementById('prime2').value;
      const e = document.getElementById('exponent').value;

      if (!p || !q || !e) return showToast("Preencha todos os campos!", false);

      try {
        const n = Module.ccall('generatePublicKey', 'string', ['string', 'string', 'string'], [p, q, e]);

        if (n.startsWith("KEY_ERROR")) throw new Error(n);

        // Exibe chaves geradas
        document.getElementById('generated-public-key').textContent = `(${e}, ${n})`;
        document.getElementById('generated-private-key').textContent = `(${p}, ${q}, ${e})`;

        // Mostra notificação
        showToast("Chave gerada com sucesso!");
      } catch (error) {
        showToast(`Erro: ${error.message}`, false);
      }
    };

    // Criptografar
    window.encryptMessage = function() {
      const publicKey = document.getElementById('public-key').value.trim();
      const message = document.getElementById('message').value.trim();

      if (!publicKey || !message) return showToast("Preencha todos os campos!", false);

      const match = publicKey.match(/\((\d+),\s*(\d+)\)/);
      if (!match) return showToast("Formato inválido! Use (e, n)", false);

      try {
        const e = match[1], n = match[2];
        const encrypted = Module.ccall('encryptMessage', 'string', ['string', 'string', 'string'], [message, n, e]);
        
        if (encrypted.startsWith("KEY_ERROR")) {
          throw new Error(encrypted.split(": ")[1] || encrypted);
        }

        document.getElementById('encrypted-output').value = encrypted;
        showToast("Mensagem criptografada com sucesso!");
        
        // Libera memória alocada pelo C
        setTimeout(() => Module._free(encrypted), 0);
      } catch (error) {
        showToast(`Erro: ${error.message}`, false);
      }
    };

    // Descriptografar
    window.decryptMessage = function() {
      const privateKey = document.getElementById('private-key').value.trim();
      const encryptedMsg = document.getElementById('message-decrypt').value.trim();

      if (!privateKey || !encryptedMsg) return showToast("Preencha todos os campos!", false);

      const match = privateKey.match(/\((\d+),\s*(\d+),\s*(\d+)\)/);
      if (!match) return showToast("Formato inválido! Use (p, q, e)", false);

      try {
        const p = match[1], q = match[2], e = match[3];
        const decrypted = Module.ccall('decryptMessage', 'string', ['string', 'string', 'string', 'string'], [encryptedMsg, p, q, e]);
        
        if (decrypted.startsWith("KEY_ERROR")) {
          throw new Error(decrypted.split(": ")[1] || decrypted);
        }

        document.getElementById('decrypted-output').value = decrypted;
        showToast("Mensagem descriptografada com sucesso!");
        
        // Libera memória alocada pelo C
        setTimeout(() => Module._free(decrypted), 0);
      } catch (error) {
        showToast(`Erro: ${error.message}`, false);
      }
    };
  };

  // Fallback caso o WASM não carregue
  setTimeout(() => {
    if (!Module.asm) {
      showToast("Erro: O módulo de criptografia não carregou. Recarregue a página.", false);
    }
  }, 5000);
});