(dfunction() {
  var widgetContainer = document.getElementById('pacepeek-widget');
  var fill = widgetContainer.getAttribute('data-fill');
  var stroke = widgetContainer.getAttribute('data-stroke');
  var text = widgetContainer.getAttribute('data-text');
  var user_login = widgetContainer.getAttribute('data-user_login');

  fetch(`https://pacepeek.com/widget_svg/${user_login}/3?fill_color=${fill}&stroke_color=${stroke}&text_color=${text}`)
        .then( response => response.text() )
        .then( data => { widgetContainer.innerHTML = data; } )
        .catch( error => { console.error('Error fetching widget:', error); } );
})();

