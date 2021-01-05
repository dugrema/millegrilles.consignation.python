import datetime

timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M")
print(timestamp)


def calculer_2_3_duree():
    date_debut = datetime.datetime(year=2021, month=1, day=1)
    date_fin = datetime.datetime(year=2021, month=6, day=30)

    # Calcul 2 tiers
    delta_fin_debut = date_fin.timestamp() - date_debut.timestamp()
    epoch_deux_tiers = delta_fin_debut / 3 * 2 + date_debut.timestamp()
    date_deuxtiers = datetime.datetime.fromtimestamp(epoch_deux_tiers)

    print("Date deux tiers : %s" % date_deuxtiers)


calculer_2_3_duree()