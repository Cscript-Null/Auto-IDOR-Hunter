// 使用 fetch
fetch('/api/data', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ key: 'value' })
});

// 使用 axios
axios.get('/api/info')
    .then(response => console.log(response));

// 使用 XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.open('PUT', '/api/update', true);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(JSON.stringify({ update: 'data' }));
