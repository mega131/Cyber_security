// Global Forensic Analyzer UI Utilities

function copyToClipboard(text, buttonElement) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = buttonElement.innerHTML;
    buttonElement.innerHTML = '✓ Copied';
    buttonElement.style.color = '#00e676';
    setTimeout(() => {
      buttonElement.innerHTML = originalText;
      buttonElement.style.color = '';
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy: ', err);
  });
}

function dismissAlert(button) {
  const alert = button.closest('.alert');
  if (alert) {
    alert.style.opacity = '0';
    setTimeout(() => alert.remove(), 200);
  }
}

// Drag and drop dropzone handlers
document.addEventListener('DOMContentLoaded', () => {
  const dropzones = document.querySelectorAll('.dropzone');
  
  dropzones.forEach(dropzone => {
    const input = dropzone.querySelector('.file-input');
    const label = dropzone.querySelector('.dropzone-text');
    
    if (!input) return;
    
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      }, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
      }, false);
    });
    
    dropzone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        updateLabel(e.dataTransfer.files[0]);
      }
    });
    
    input.addEventListener('change', () => {
      if (input.files.length) {
        updateLabel(input.files[0]);
      }
    });
    
    function updateLabel(file) {
      if (label) {
        label.innerHTML = `<strong>Selected:</strong> ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        label.style.color = '#00e5ff';
      }
    }
  });
});
