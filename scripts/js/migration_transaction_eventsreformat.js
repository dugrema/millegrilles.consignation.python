var nomMilleGrille = 'sansnom';
var listeDomaines = [
'millegrilles.domaines.GrosFichiers',
'millegrilles.domaines.MaitreDesCles',
'millegrilles.domaines.Parametres',
'millegrilles.domaines.Plume',
'millegrilles.domaines.Principale',
'millegrilles.domaines.SenseursPassifs',
]

function maj_collections(listeDomaines) {
    for(let idx in listeDomaines) {
        let domaine = listeDomaines[idx];
        let collection = db[domaine];
        maj(collection);
    }
}

function maj(collection) {
    let curseur = collection.find({});

    while(curseur.hasNext()) {
        let row = curseur.next();
        let docId = row['_id'];
        let mgEvenements = map_row(row);
        let transactionComplete = false;
        if(mgEvenements['transaction_traitee']) {
            transactionComplete = true;
        }
        let ops = {
            '$set': {
                '_evenements.sansnom': mgEvenements,
                '_evenements.transaction_complete': transactionComplete
            }
        }

        print("Update: " + docId);
        collection.updateOne({'_id': docId}, ops);
    }
};

function map_row(row) {
    let evenementsMG = row['_evenements'][nomMilleGrille];
    let mgEvenements = {};
    for(let nomEvent in evenementsMG) {
        let listeDates = evenementsMG[nomEvent];
        let dateFixed = listeDates;
        // Enlever la collection
        if(dateFixed[0]) {
            dateFixed = dateFixed[0];
        }
        mgEvenements[nomEvent] = dateFixed;
    }

    return mgEvenements;
}

/*
maj_collections(listeDomaines);
*/
