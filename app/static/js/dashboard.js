// Dashboard Chart.js Visualizations (Modern Clean Light Theme)
document.addEventListener('DOMContentLoaded', () => {
  fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
      initTypeChart(data.type_distribution);
      initIntegrityChart(data.total_verifications, data.matched_count, data.mismatch_count);
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

function initIntegrityChart(total, matched, mismatched) {
  const ctx = document.getElementById('integrityChart');
  if (!ctx) return;
  
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Total Audits', 'Verified Matches', 'Mismatches'],
      datasets: [{
        label: 'Verifications',
        data: [total, matched, mismatched],
        backgroundColor: [
          '#0284c7',
          '#16a34a',
          '#dc2626'
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
