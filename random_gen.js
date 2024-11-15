function capFirst(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

function getRandomInt(min, max) {
      return Math.floor(Math.random() * (max - min)) + min;
}

function generateName1(){
    var name1 = ["Harry","Ross",
    "Bruce","Cook","Carolyn","Morgan","Albert","Walker","Randy","Reed",
    "Larry","Barnes","Lois","Wilson","Jesse","Campbell","Ernest","Rogers",
    "Theresa","Patterson","Henry","Simmons","Michelle","Perry","Frank","Butler","Shirley","Brooks","Rachel","Edwards","Christopher","Perez",
    "Thomas","Baker","Sara","Moore","Chris","Bailey","Roger","Johnson",
    "Marilyn","Thompson","Anthony","Evans","Julie","Hall","Paula","Phillips","Annie","Hernandez","Dorothy","Murphy","Alice","Howard",
    "Ruth","Jackson","Debra","Allen","Gerald","Harris","Raymond","Carter",
    "Jacqueline","Torres","Joseph","Nelson","Carlos","Sanchez","Ralph","Clark","Jean","Alexander","Stephen","Roberts","Eric","Long","Amanda","Scott","Teresa","Diaz","Wanda","Thomas"];
    var name = capFirst(name1[getRandomInt(0, name1.length + 1)]);

    return name;
}
function generateName2(){

    var name2 =[ "Anderson", "Ashwoon", "Aikin", "Bateman", "Bongard", "Bowers", "Boyd", "Cannon", "Cast", "Deitz", "Dewalt", "Ebner", "Frick", "Hancock", "Haworth", "Hesch", "Hoffman", "Kassing", "Knutson", "Lawless", "Lawicki", "Mccord", "McCormack", "Miller", "Myers", "Nugent", "Ortiz", "Orwig", "Ory", "Paiser", "Pak", "Pettigrew", "Quinn", "Quizoz", "Ramachandran", "Resnick", "Sagar", "Schickowski", "Schiebel", "Sellon", "Severson", "Shaffer", "Solberg", "Soloman", "Sonderling", "Soukup", "Soulis", "Stahl", "Sweeney", "Tandy", "Trebil", "Trusela", "Trussel", "Turco", "Uddin", "Uflan", "Ulrich", "Upson", "Vader", "Vail", "Valente", "Van Zandt", "Vanderpoel", "Ventotla", "Vogal", "Wagle", "Wagner", "Wakefield", "Weinstein", "Weiss", "Woo", "Yang", "Yates", "Yocum", "Zeaser", "Zeller", "Ziegler", "Bauer", "Baxster", "Casal", "Cataldi", "Caswell", "Celedon", "Chambers", "Chapman", "Christensen", "Darnell", "Davidson", "Davis", "DeLorenzo", "Dinkins", "Doran", "Dugelman", "Dugan", "Duffman", "Eastman", "Ferro", "Ferry", "Fletcher", "Fietzer", "Hylan", "Hydinger", "Illingsworth", "Ingram", "Irwin", "Jagtap", "Jenson", "Johnson", "Johnsen", "Jones", "Jurgenson", "Kalleg", "Kaskel", "Keller", "Leisinger", "LePage", "Lewis", "Linde", "Lulloff", "Maki", "Martin", "McGinnis", "Mills", "Moody", 
   "Moore", "Napier", "Nelson", "Norquist", "Nuttle", "Olson", 
   "Ostrander", 
  "Reamer", "Reardon", "Reyes", "Rice", "Ripka", "Roberts", "Rogers", 
   "Root", 
  "Sandstrom", "Sawyer", "Schlicht", "Schmitt", "Schwager", "Schutz", 
  "Schuster", "Tapia", "Thompson", "Tiernan", "Tisler" ]; 

    var name12 = capFirst(name2[getRandomInt(0, name2.length + 1)]);
    return name12;``
}


 console.log( generateName1() )