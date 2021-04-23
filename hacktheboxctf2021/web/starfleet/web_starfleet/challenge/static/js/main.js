const alerts  = document.getElementById('alerts');
const loading = document.getElementById('loading');
const output  = document.getElementById('output');
const form    = document.getElementById('form');

const flash = (message, level) => {
    alerts.innerHTML += `
        <div class="alert alert-${level}" role="alert">
            <button type="button" id="closeAlert" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
            <strong>${message}</strong>
        </div>
    `;
};

form.addEventListener('submit', e => {
	e.preventDefault();

	loading.style.display = 'block';

	fetch('/api/enroll', {
		method: 'POST',
		body: JSON.stringify({
			'email': document.querySelector('input[type=text]').value
		}),
		headers: {'Content-Type': 'application/json'}
	})
	.then(resp => resp.json())
	.then(resp => {
		if (resp.response.includes('http')) {
			output.innerHTML = resp.response;
		} else {
			if (resp.error) {
				flash(resp.response, 'danger');

				setTimeout(() => {
					document.getElementById('closeAlert').click();
				}, 2800);
			}

			if (!resp.error) {
				flash(resp.response, 'success');

				setTimeout(() => {
					document.getElementById('closeAlert').click();
				}, 2800);
			}
		}
	})
	.then(() => {
		loading.style.display = 'none';
	})
});