function myLocaleLang(){
    let lang = navigator.language;
    if (lang == 'en-US') {
      var result = moment.locale('en');
    } else {
      var result = moment.locale('es');
    }
    return result;
  }
myLocaleLang();
let lang = navigator.language;
console.log(lang);

