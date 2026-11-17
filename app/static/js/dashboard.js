// Dashboard Chart.js Visualizations (Modern Clean Light Theme with AI & Blockchain)
document.addEventListener('DOMContentLoaded', () => {
  fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
      initTypeChart(data.type_distribution);
      initAIThreatChart(data.ai_threat_stats, data.matched_count, data.mismatch_count);
    })
    .catch(err => console.error('Failed to load dashboard metrics: ', err));
});

function initTypeChart(distribution) {
  const ctx = document.getElementById('typeChart');
  if (!ctx) return;
  
  const labels = Object.keys(distribution);
  const counts = Object.values(distribution);
  
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: counts,
        backgroundColor: [
          '#0284c7', // Sky blue
          '#2563eb', // Indigo/Blue
          '#16a34a', // Emerald green
          '#9333ea', // Purple
          '#64748b'  // Slate
        ],
        borderColor: '#ffffff',
        borderWidth: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#475569',
            font: { family: "'Plus Jakarta Sans', sans-serif", size: 12, weight: 600 },
            padding: 15
          }
        }
      },
      cutout: '70%'
    }
  });
}

function initAIThreatChart(aiThreatStats, matched, mismatched) {
  const ctx = document.getElementById('integrityChart');
  if (!ctx) return;
  
  const lowCount = (aiThreatStats && aiThreatStats.LOW) || 0;
  const elevatedCount = (aiThreatStats && aiThreatStats.ELEVATED) || 0;
  const suspiciousCount = (aiThreatStats && aiThreatStats.SUSPICIOUS) || 0;
  const criticalCount = (aiThreatStats && aiThreatStats.CRITICAL) || 0;
  
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['AI Safe (Low)', 'AI Elevated', 'AI Suspicious', 'AI Critical', 'Hash Verified', 'Hash Breach'],
      datasets: [{
        label: 'Artifacts',
        data: [lowCount, elevatedCount, suspiciousCount, criticalCount, matched, mismatched],
        backgroundColor: [
          '#16a34a', // Low - Green
          '#0284c7', // Elevated - Sky
          '#d97706', // Suspicious - Amber
          '#dc2626', // Critical - Red
          '#10b981', // Hash Verified - Emerald
          '#ef4444'  // Hash Breach - Red
        ],
        borderRadius: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            color: '#475569',
            font: { family: "'Plus Jakarta Sans', sans-serif", size: 11 },
            precision: 0
          },
          grid: { color: 'rgba(0, 0, 0, 0.06)' }
        },
        x: {
          ticks: {
            color: '#475569',
            font: { family: "'Plus Jakarta Sans', sans-serif", size: 11, weight: 600 }
          },
          grid: { display: false }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}
