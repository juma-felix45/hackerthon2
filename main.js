// main.js
const userId = 1; // demo user
document.addEventListener('DOMContentLoaded', init);

function init() {
  const textForm = document.getElementById('textForm');
  const imageForm = document.getElementById('imageForm');

  textForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = document.getElementById('text').value;
    const form = new FormData();
    form.append('text', text);
    form.append('user_id', userId);
    const res = await fetch('/submit_text', { method: 'POST', body: form });
    const data = await res.json();
    displayResult(data);
    loadHistoryAndPlot();
  });

  imageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = document.getElementById('image').files[0];
    const form = new FormData();
    form.append('image', file);
    form.append('user_id', userId);
    const res = await fetch('/upload_image', { method: 'POST', body: form });
    const data = await res.json();
    displayResult(data);
    loadHistoryAndPlot();
  });

  loadHistoryAndPlot();
}

function displayResult(data){
  const el = document.getElementById('latest');
  if (data.error) {
    el.innerHTML = `<div class="err">Error: ${data.error}</div>`;
    return;
  }
  const label = data.label || 'unknown';
  const scores = data.scores || {};
  el.innerHTML = `<strong>${label}</strong><pre>${JSON.stringify(scores,null,2)}</pre>`;
}

let moodChart = null;
async function loadHistoryAndPlot() {
  const resp = await fetch(`/history/${userId}`);
  const history = await resp.json();
  // reduce to daily average of 'happy' score (as an example)
  const dates = history.map(h => (new Date(h.created_at)).toLocaleString());
  const labels = history.map(h => h.created_at.split('T')[0]);
  // Convert each to top emotion score value (choose 'happy' or top)
  const vals = history.map(h => {
    const scores = h.scores || {};
    // try to take an overall positivity metric: happy + surprise - sadness - anger
    const happy = scores.happy || scores.joy || 0;
    const sad = scores.sad || 0;
    const anger = scores.angry || 0;
    const surprise = scores.surprise || 0;
    const metric = (happy + surprise) - (sad + anger);
    return Math.round(metric * 100);
  });

  const ctx = document.getElementById('moodChart').getContext('2d');
  if (moodChart) moodChart.destroy();
  moodChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: dates,
      datasets: [{
        label: 'Mood score',
        data: vals,
        fill: true,
        tension: 0.2,
        pointRadius: 4,
      }]
    },
    options: {
      responsive: true,
      scales: { y: { beginAtZero: true } }
    }
  });
}
