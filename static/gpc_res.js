const dateTimeElem = document.getElementById('updateDateTime');
const dateTime = new Date(dateTimeElem.textContent);
dateTimeElem.textContent = dateTime.toLocaleString();
