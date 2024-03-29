import logging
import math
import multibase
import gzip
import json
import requests
import datetime

from os import path
from io import BytesIO
from typing import Union
from pymongo import ReturnDocument

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPublication, ConstantesGrosFichiers, ConstantesMaitreDesCles
from millegrilles.MGProcessus import MGProcessus
from millegrilles.util.Hachage import hacher
from millegrilles.util.JSONMessageEncoders import JSONHelper
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.util.Chiffrage import CipherMsg2Chiffrer, CipherMsg2Dechiffrer
from millegrilles.SecuritePKI import EnveloppeCertificat


# Operations pour invalider une ressource
UNSET_PUBLICATION_RESOURCES = {
    ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: True,
    ConstantesPublication.CHAMP_DISTRIBUTION_PUBLIC_COMPLETE: True,
    ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: True,
    ConstantesPublication.CHAMP_DISTRIBUTION_MAJ: True,
    # ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: True,
    # ConstantesPublication.CHAMP_CONTENU_GZIP: True,
    # ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
    ConstantesPublication.CHAMP_DATE_SIGNATURE: True,
}


class InvalidateurRessources:

    def __init__(self, cascade):
        self.__cascade = cascade

    @property
    def document_dao(self):
        return self.__cascade.document_dao

    def marquer_ressource_encours(self, cdn_id, filtre_ressource, many=False, etat=True, upsert=False):
        date_courante = datetime.datetime.utcnow()
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: date_courante,
        }
        set_on_insert.update(filtre_ressource)
        ops = {
            '$set': {'distribution_progres.' + cdn_id: etat},
            '$currentDate': {
                'distribution_maj': True,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
            }
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        if many is False:
            collection_ressources.update_one(filtre_ressource, ops, upsert=upsert)
        else:
            collection_ressources.update_many(filtre_ressource, ops, upsert=upsert)

    def reset_ressources_encours(self, site_id: str = None):
        ops = {
            '$unset': {
                ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: True,
                ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: True,
            },
            '$currentDate': {
                'distribution_maj': True,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
            }
        }
        filtre = {
            '$or': [
                {ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'$exists': True}},
                {ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: {'$exists': True}},
            ]
        }

        if site_id is not None:
            filtre['site_id'] = site_id

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        collection_ressources.update_many(filtre, ops)

    def marquer_ressource_complete(self, cdn_id, filtre_ressource, many=False):
        date_courante = datetime.datetime.utcnow()
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: date_courante,
        }
        set_on_insert.update(filtre_ressource)
        ops = {
            '$unset': {'distribution_progres.' + cdn_id: True},
            '$addToSet': {ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: cdn_id},
            '$currentDate': {
                'distribution_maj': True,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
            }
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        if many is False:
            collection_ressources.update_one(filtre_ressource, ops)
        else:
            collection_ressources.update_many(filtre_ressource, ops)

    def invalider_ressources_siteconfig(self, site_id: Union[str, list] = None, cdn_ids: list = None):
        """
        Enlever marqueurs de deploiement pour les sites
        :param site_id:
        :param cdn_ids:
        :return:
        """
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG
        }

        if site_id is not None:
            if isinstance(site_id, str):
                site_id = [site_id]
            filtre[ConstantesPublication.CHAMP_SITE_ID] = {'$in': site_id}
        if cdn_ids is not None:
            label_cdn = ['contenu', 'cdns', ConstantesPublication.CHAMP_CDN_ID]
            filtre[label_cdn] = {'$in': cdn_ids}

        self.invalider_ressources(filtre)

    def invalider_ressource_mapping(self):
        """
        Enlever marqueurs de deploiement pour les sites
        :return:
        """
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING
        }
        self.invalider_ressources(filtre)

    def invalider_ressources_pages(self, section_ids: list = None):
        """
        Enlever marqueurs de deploiement pour les sections de type page
        :param section_ids:
        :return:
        """
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SECTION_PAGE,
            ConstantesPublication.CHAMP_SECTION_ID: {'$in': section_ids}
        }
        self.invalider_ressources(filtre)

    def invalider_ressources_sections_fichiers(self, section_ids: list = None):
        """
        Enlever marqueurs de deploiement pour les sections de type fichiers
        :param section_ids:
        :return:
        """
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'uuid': {'$in': section_ids}
        }
        self.invalider_ressources(filtre)

    def invalider_ressources(self, filtre: dict):
        """
        Enlever marqueurs de deploiement pour les sites
        :param filtre:
        :return:
        """
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        unset_ops = UNSET_PUBLICATION_RESOURCES.copy()
        unset_ops[ConstantesPublication.CHAMP_CONTENU] = True
        ops = {
            '$unset': unset_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        collection_ressources.update(filtre, ops)

    def marquer_ressource_erreur(self, filtre_ressource, err_code: str = None, cdn_id: str = None):
        if cdn_id is not None:
            unset = {'$unset': {'distribution_progres.' + cdn_id: True}}
        else:
            unset = {'$unset': {'distribution_progres': True}}

        if err_code is not None:
            set_ops = {ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: err_code}
        else:
            set_ops = {ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: True}

        ops = {
            '$unset': unset,
            '$set': set_ops,
            '$addToSet': {ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: cdn_id},
            '$currentDate': {
                'distribution_maj': True,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
            }
        }

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        collection_ressources.update_many(filtre_ressource, ops)

    def marquer_collection_fichiers_prete(self, uuid_collection: str):
        set_ops = {
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'uuid': uuid_collection,
        }
        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        doc_fichiers = collection_ressources.find_one_and_update(filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        cdns = set()
        try:
            progres = doc_fichiers.get(ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES)
            cdns.update(progres.keys())
        except (AttributeError, TypeError):
            pass  #OK

        try:
            complete = doc_fichiers.get(ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE)
            cdns.update(complete)
        except TypeError:
            pass  # OK

        # Ajouter tous les CDN associes a cette collection aux fichiers de la collection (res)
        for cdn_id in cdns:
            # Marquer les fichiers de la collection qui n'ont pas ete publies sur le CDN
            filtre_fichiers = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
                'collections': {'$all': [uuid_collection]},
                ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: {'$not': {'$all': [cdn_id]}}
            }
            label_progres = ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id
            set_ops = {
                label_progres: False,
            }
            ops = {
                '$set': set_ops,
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            }
            collection_ressources.update_many(filtre_fichiers, ops)

        return doc_fichiers


class RessourcesPublication:

    def __init__(self, cascade):
        self.__cascade = cascade
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    @property
    def document_dao(self):
        return self.__cascade.document_dao

    def maj_ressource_mapping(self):
        # Trouver les sites a mapper. On ne va pas mapper les sites avec 0 CDN actif.
        sites = self.trouver_sites_avec_cdns_actifs()

        collection_configuration = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CONFIGURATION_NOM)
        doc_mapping = collection_configuration.find_one({Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING}) or dict()
        site_id_defaut = doc_mapping.get(ConstantesPublication.CHAMP_SITE_DEFAUT)

        if site_id_defaut is not None:
            # Le site id a ete specifie dans la configuration
            pass
        elif len(sites) == 1:
            # Un seul site disponible
            site_defaut = list(sites.values())[0]
            site_id_defaut = site_defaut[ConstantesPublication.CHAMP_SITE_ID]

        configuration_par_url = dict()
        mapping = {
            'sites': configuration_par_url,
        }

        # Creer la liste des siteconfig
        cdns = dict()
        if len(sites) > 0:
            liste_siteconfigs = list()
            for site in sites.values():
                site_id = site[ConstantesPublication.CHAMP_SITE_ID]

                # Note : La methode genere le contenu uniquement s'il n'est pas deja present
                doc_res_site = self.preparer_siteconfig_publication(site_id)
                contenu = doc_res_site[ConstantesPublication.CHAMP_CONTENU]
                contenu_signe = doc_res_site[ConstantesPublication.CHAMP_CONTENU_SIGNE]

                liste_siteconfigs.append(contenu_signe)

                for cdn_site in contenu['cdns']:
                    cdns[cdn_site[ConstantesPublication.CHAMP_CDN_ID]] = cdn_site

                information_site = {
                    ConstantesPublication.CHAMP_SITE_ID: site_id,
                    Constantes.DOCUMENT_INFODOC_SECURITE: site[Constantes.DOCUMENT_INFODOC_SECURITE],
                }
                try:
                    information_site[ConstantesPublication.CHAMP_IPNS_ID] = site[ConstantesPublication.CHAMP_IPNS_ID]
                except KeyError:
                    pass  # Ok

                if site_id_defaut == site_id:
                    mapping[ConstantesPublication.CHAMP_SITE_DEFAUT] = information_site

                try:
                    for domaine in site[ConstantesPublication.CHAMP_LISTE_DOMAINES]:
                        configuration_par_url[domaine] = information_site
                except KeyError:
                    pass  # Ok

        mapping['cdns'] = list(cdns.values())

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),

        }
        set_on_insert.update(filtre)
        set_ops = {
            ConstantesPublication.CHAMP_CONTENU: mapping,
        }
        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        doc_mapping = collection_ressources.find_one_and_update(
            filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        return doc_mapping

    def trouver_sites_avec_cdns_actifs(self):
        """
        :return: List de sites avec au moins 1 CDN actif
        """
        filtre_cdn_actifs = {ConstantesPublication.CHAMP_ACTIVE: True}
        curseur_cdn = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS).find(filtre_cdn_actifs)
        cdns = set()
        for cdn in curseur_cdn:
            cdn_id = cdn[ConstantesPublication.CHAMP_CDN_ID]
            cdns.add(cdn_id)

        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        filtre_sites_avec_cdns = {
            ConstantesPublication.CHAMP_LISTE_CDNS: {'$in': list(cdns)}
        }

        sites = dict()
        for site in collection_sites.find(filtre_sites_avec_cdns):
            site_id = site[ConstantesPublication.CHAMP_SITE_ID]
            sites[site_id] = site

        return sites

    def maj_ressources_site(self, params: dict):
        site_id = params[ConstantesPublication.CHAMP_SITE_ID]
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
        }
        doc_site = collection_sites.find_one(filtre)

        champs_site = [
            ConstantesPublication.CHAMP_SITE_ID,
            ConstantesPublication.CHAMP_LANGUAGES,
            ConstantesPublication.CHAMP_TITRE,
            Constantes.DOCUMENT_INFODOC_SECURITE,
            ConstantesPublication.CHAMP_LISTE_SOCKETIO,
        ]
        contenu = {
            ConstantesPublication.CHAMP_TYPE_SECTION: ConstantesPublication.LIBVAL_SITE_CONFIG,
        }
        for key, value in doc_site.items():
            if key in champs_site:
                contenu[key] = value

        # Ajouter tous les CDNs pour ce site, en ordre de preference
        contenu['cdns'] = self.mapper_cdns_pour_site(site_id)

        # Aller chercher references des sections
        # Chaque section est un fichier accessible via son uuid
        liste_sections_id = doc_site.get(ConstantesPublication.CHAMP_LISTE_SECTIONS)
        if liste_sections_id is not None:
            contenu[ConstantesPublication.CHAMP_LISTE_SECTIONS] = self.mapper_sections_pour_site(liste_sections_id)

        # Aller chercher les valeurs ipfs (CID) pour tous les champs uuid (si applicable)
        cid_site, uuid_to_ipfs = self.mapper_site_ipfs(site_id)
        if cid_site is not None:
            contenu['cid'] = cid_site
        if len(uuid_to_ipfs) > 0:
            contenu['ipfs_map'] = uuid_to_ipfs

        set_on_insert = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        set_ops = {
            'contenu': contenu,
            'sites': [site_id],
        }
        ops = {
            '$set': set_ops,
            '$unset': UNSET_PUBLICATION_RESOURCES,
            '$setOnInsert': set_on_insert,
            '$currentDate': {ConstantesPublication.CHAMP_DATE_MODIFICATION: True},
        }
        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        doc_site = collection_ressources.find_one_and_update(
            filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        return doc_site

    def mapper_site_ipfs(self, site_id):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre_res_ipns = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                ConstantesPublication.LIBVAL_SECTION_PAGE,
                ConstantesPublication.LIBVAL_SECTION_FORUMS,
                ConstantesPublication.LIBVAL_SITE_CONFIG,
            ]},
            'sites': {'$all': [site_id]},
            'cid': {'$exists': True},
        }
        projection = {'cid': True, 'uuid': True, 'section_id': True, Constantes.DOCUMENT_INFODOC_LIBELLE: True}
        curseur_res_cid = collection_ressources.find(filtre_res_ipns, projection=projection)
        uuid_to_ipfs = dict()
        cid_site = None
        for elem in curseur_res_cid:
            type_res = elem[Constantes.DOCUMENT_INFODOC_LIBELLE]
            cid = elem['cid']
            if type_res == ConstantesPublication.LIBVAL_SITE_CONFIG:
                # Le site est conserve separement (meme uuid que sa collection de fichiers)
                cid_site = cid
            else:
                id_elem = elem.get('uuid') or elem.get('section_id')
                uuid_to_ipfs[id_elem] = cid
        return cid_site, uuid_to_ipfs

    def mapper_sections_pour_site(self, liste_sections_id):
        sections_liste = list()
        filtre_sections = {
            ConstantesPublication.CHAMP_SECTION_ID: {'$in': liste_sections_id}
        }
        collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
        curseur_sections = collection_sections.find(filtre_sections)
        sections_dict = dict()
        for s in curseur_sections:
            sections_dict[s[ConstantesPublication.CHAMP_SECTION_ID]] = s
        # Ajouter sections en ordre
        uuid_to_map = set()  # Conserver tous les uuid a mapper
        for section_id in liste_sections_id:
            doc_section = sections_dict[section_id]
            type_section = doc_section[ConstantesPublication.CHAMP_TYPE_SECTION]

            section = {
                ConstantesPublication.CHAMP_TYPE_SECTION: type_section,
                ConstantesPublication.CHAMP_ENTETE: doc_section.get(ConstantesPublication.CHAMP_ENTETE),
            }

            if type_section in [ConstantesPublication.LIBVAL_SECTION_FICHIERS,
                                ConstantesPublication.LIBVAL_SECTION_ALBUM]:
                uuid_collections = doc_section.get(ConstantesPublication.CHAMP_COLLECTIONS)
                if uuid_collections is not None:
                    section[ConstantesPublication.CHAMP_COLLECTIONS] = uuid_collections
                    uuid_to_map.update(uuid_collections)
            elif type_section == ConstantesPublication.LIBVAL_SECTION_FORUMS:
                section[ConstantesPublication.CHAMP_LISTE_FORUMS] = doc_section[ConstantesPublication.CHAMP_LISTE_FORUMS]
            else:
                section[ConstantesPublication.CHAMP_SECTION_ID] = section_id
                uuid_to_map.add(section_id)

            sections_liste.append(section)
        return sections_liste

    def mapper_cdns_pour_site(self, site_id: str):
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        doc_site = collection_sites.find_one({ConstantesPublication.CHAMP_SITE_ID: site_id})
        liste_cdn_ids = doc_site['listeCdn']

        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        filtre_cdns = {'cdn_id': {'$in': liste_cdn_ids}, 'active': True}
        curseur_cdns = collection_cdns.find(filtre_cdns)
        mapping_cdns = dict()
        for cdn in curseur_cdns:
            mapping = {
                'type_cdn': cdn['type_cdn'],
                'cdn_id': cdn['cdn_id'],
            }
            access_point_url = cdn.get('accesPointUrl')
            if access_point_url is not None:
                mapping['access_point_url'] = access_point_url

            mapping_cdns[cdn['cdn_id']] = mapping
        mapping_cdns = [mapping_cdns[cdn_id] for cdn_id in liste_cdn_ids if cdn_id in mapping_cdns.keys()]
        return mapping_cdns

    def maj_ressources_page(self, params: dict):
        section_id = params[ConstantesPublication.CHAMP_SECTION_ID]

        # Formatter les parties page, fuuids
        fuuids_info, parties_page_ordonnees, site_id, doc_page = self.formatter_parties_page(section_id)
        fuuids = self.formatter_fuuids_page(fuuids_info)

        contenu = {
            ConstantesPublication.CHAMP_TYPE_SECTION: ConstantesPublication.LIBVAL_SECTION_PAGE,
            ConstantesPublication.CHAMP_SECTION_ID: section_id,
            ConstantesPublication.CHAMP_PARTIES_PAGES: parties_page_ordonnees,
            'fuuids': fuuids,
        }
        if doc_page.get(Constantes.DOCUMENT_INFODOC_SECURITE):
            contenu[Constantes.DOCUMENT_INFODOC_SECURITE] = doc_page[Constantes.DOCUMENT_INFODOC_SECURITE]

        set_ops = {
            'contenu': contenu,
            'sites': [site_id],
        }
        set_on_insert = {
            ConstantesPublication.CHAMP_SECTION_ID: section_id,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SECTION_PAGE,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {ConstantesPublication.CHAMP_DATE_MODIFICATION: True},
        }
        filtre = {
            ConstantesPublication.CHAMP_SECTION_ID: section_id,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SECTION_PAGE,
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        doc_page = collection_ressources.find_one_and_update(
            filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        # Ajouter les fichiers requis comme ressource pour le site
        doc_site = self.__cascade.get_site(site_id)
        flag_public = doc_site['securite'] == Constantes.SECURITE_PUBLIC
        self.maj_ressources_fuuids(fuuids_info, public=flag_public)

        return doc_page

    def formatter_fuuids_page(self, fuuids_info: dict):
        fuuids = dict()
        for finfo in fuuids_info.values():
            fm = finfo.get(ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES)
            if fm is not None:
                for fuuid, mimetype in fm.items():
                    try:
                        fuuid_info = fuuids[fuuid]
                    except KeyError:
                        fuuid_info = dict()
                        fuuids[fuuid] = fuuid_info
                    fuuid_info['mimetype'] = mimetype
        # Associer tous les CID (fichiers) aux ressources dans la liste
        filtre_res_fichiers = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            'fuuid': {'$in': list(fuuids.keys())},
        }

        projection_res_fichiers = {'fuuid': True, 'public': True, 'cid_public': True, 'cid': True}
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        curseur_res_fichiers = collection_ressources.find(filtre_res_fichiers, projection=projection_res_fichiers)
        for info_fichier in curseur_res_fichiers:
            fuuid = info_fichier['fuuid']
            flag_public = info_fichier.get('public') or False
            cid_public = info_fichier.get('cid_public')
            cid = info_fichier.get('cid')

            try:
                fuuid_info = fuuids[fuuid]
            except KeyError:
                fuuid_info = dict()
                fuuids[fuuid] = fuuid_info

            if flag_public is True and cid_public is not None:
                fuuid_info['cid'] = cid_public
                fuuid_info['public'] = True
            elif cid is not None:
                fuuid_info['cid'] = cid
        return fuuids

    def formatter_parties_page(self, section_id):
        collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)

        filtre = {
            ConstantesPublication.CHAMP_SECTION_ID: section_id
        }

        section = collection_sections.find_one(filtre)
        site_id = section[ConstantesPublication.CHAMP_SITE_ID]
        parties_page_ordonnees = list()
        fuuids_info = dict()

        parties_page_ids = section.get(ConstantesPublication.CHAMP_PARTIES_PAGES)
        if parties_page_ids is not None and parties_page_ids != '':
            collection_partiespage = self.document_dao.get_collection(ConstantesPublication.COLLECTION_PARTIES_PAGES)
            filtre_partiespage = {
                ConstantesPublication.CHAMP_PARTIEPAGE_ID: {'$in': parties_page_ids}
            }
            curseur_parties = collection_partiespage.find(filtre_partiespage)
            parties_page = dict()
            for p in curseur_parties:
                pp_id = p[ConstantesPublication.CHAMP_PARTIEPAGE_ID]
                pp = dict()
                for key, value in p.items():
                    if not key.startswith('_'):
                        pp[key] = value
                if p.get('media'):
                    fuuids_media = p['media'].get('fuuids')
                    for fm in fuuids_media:
                        fuuids_info[fm] = p['media']
                elif p.get('colonnes'):
                    for c in p['colonnes']:
                        media = c.get('media')
                        if media is not None:
                            fuuids_media = media.get('fuuids')
                            for fm in fuuids_media:
                                fuuids_info[fm] = media

                parties_page[pp_id] = pp

            for pp_id in section[ConstantesPublication.CHAMP_PARTIES_PAGES]:
                parties_page_ordonnees.append(parties_page[pp_id])

        return fuuids_info, parties_page_ordonnees, site_id, section

    def maj_ressources_fuuids(self, fuuids_info: dict, public=False):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        collections_fichiers_uuids = set()

        for fuuid, info in fuuids_info.items():

            # Verifier si on a un video - cas d'exception, on n'upload pas la version originale du video
            # Seules les versions converties sont uploadees
            try:
                version_courante = info['version_courante']
                mimetype = version_courante[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE]
                if mimetype.startswith('video/'):
                    if fuuid == version_courante[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]:
                        continue  # Ignorer le fuuid (original)
            except KeyError:
                pass  # OK

            set_on_insert = {
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
                'fuuid': fuuid,
            }

            # Conserver information collections, va servir a invalider les sections 'fichiers'
            collections_uuids = info.get('collections') or list()
            collections_fichiers_uuids.update(collections_uuids)

            set_ops = {
                'collections': collections_uuids,
            }
            push_ops = dict()
            add_to_set_ops = dict()

            if public is True:
                set_ops['public'] = True

            try:
                fuuid_mimetypes = info[ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES]
                set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = fuuid_mimetypes[fuuid]
            except KeyError:
                if fuuid == info['fuuid_v_courante']:
                    set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = info['mimetype']
                else:
                    self.__logger.exception("Erreur traitement publication %s", fuuid)

            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
                'fuuid': fuuid,
            }
            ops = {
                '$setOnInsert': set_on_insert,
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
            }
            if len(set_ops) > 0:
                ops['$set'] = set_ops
            if len(push_ops) > 0:
                ops['$push'] = push_ops
            if len(add_to_set_ops) > 0:
                ops['$addToSet'] = add_to_set_ops
            collection_ressources.find_one_and_update(filtre, ops, upsert=True)

    def get_ressource_collection_fichiers(self, uuid_collection):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }
        res_collection = collection_ressources.find_one(filtre)
        return res_collection

    def trouver_ressources_manquantes(self, site_id: str = None):
        """
        Identifie et ajoute toutes les ressources manquantes a partir des siteconfigs et sections.
        :return:
        """
        in_site_id = site_id
        date_courante = datetime.datetime.utcnow()
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        # Verifier s'il manque des sites
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        projection_sites = {
            ConstantesPublication.CHAMP_SITE_ID: True,
            ConstantesPublication.CHAMP_IPNS_ID: True,
            ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE: True,
        }

        filtre_sites = dict()
        if in_site_id is not None:
            filtre_sites['site_id'] = in_site_id

        curseur_sites = collection_sites.find(filtre_sites, projection=projection_sites)
        # site_ids = [s[ConstantesPublication.CHAMP_SITE_ID] for s in curseur_sites]
        for doc_site in curseur_sites:
            site_id = doc_site[ConstantesPublication.CHAMP_SITE_ID]
            ipns_id = doc_site.get(ConstantesPublication.CHAMP_IPNS_ID)
            ipns_cle_chiffree = doc_site.get(ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE)

            set_on_insert = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,
                ConstantesPublication.CHAMP_SITE_ID: site_id,
            }
            set_ops = {
                ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
            }
            if ipns_id and ipns_cle_chiffree:
                set_ops[ConstantesPublication.CHAMP_IPNS_ID] = ipns_id
                set_ops[ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE] = ipns_cle_chiffree

            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
                ConstantesPublication.CHAMP_SITE_ID: site_id,
            }

            ops = {
                '$set': set_ops,
                '$setOnInsert': set_on_insert
            }
            collection_ressources.update_one(filtre, ops, upsert=True)

        # Verifier s'il manque des sections (pages, collections fichiers)
        collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)

        filtre_sections = dict()
        if in_site_id is not None:
            filtre_sections['site_id'] = in_site_id

        curseur_sections = collection_sections.find(filtre_sections)
        for section in curseur_sections:
            type_section = section[ConstantesPublication.CHAMP_TYPE_SECTION]
            ipns_id = section.get(ConstantesPublication.CHAMP_IPNS_ID)
            ipns_cle_chiffree = section.get(ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE)

            site_id = section.get(ConstantesPublication.CHAMP_SITE_ID)
            section_id = section[ConstantesPublication.CHAMP_SECTION_ID]

            set_on_insert = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: type_section,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,

            }
            if type_section == ConstantesPublication.LIBVAL_COLLECTION_FICHIERS:
                set_on_insert['uuid'] = section_id
            else:
                set_on_insert[ConstantesPublication.CHAMP_SECTION_ID] = section_id

            if site_id:
                set_on_insert[ConstantesPublication.CHAMP_SITE_ID] = site_id

            set_ops = {
                ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
            }
            if ipns_id and ipns_cle_chiffree:
                set_ops[ConstantesPublication.CHAMP_IPNS_ID] = ipns_id
                set_ops[ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE] = ipns_cle_chiffree

            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: type_section,
                ConstantesPublication.CHAMP_SECTION_ID: section[ConstantesPublication.CHAMP_SECTION_ID],
            }

            ops = {
                '$set': set_ops,
                '$setOnInsert': set_on_insert
            }
            collection_ressources.update_one(filtre, ops, upsert=True)

        collection_configuration = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CONFIGURATION_NOM)
        filtre_configuration = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [ConstantesPublication.LIBVAL_WEBAPPS]}
        }
        curseur_configurations = collection_configuration.find(filtre_configuration)
        for configuration in curseur_configurations:
            type_configuration = configuration[Constantes.DOCUMENT_INFODOC_LIBELLE]
            ipns_id = configuration.get(ConstantesPublication.CHAMP_IPNS_ID)
            ipns_cle_chiffree = configuration.get(ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE)

            set_on_insert = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: type_configuration,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,
            }
            set_ops = {
                ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
            }
            if ipns_id and ipns_cle_chiffree:
                set_ops[ConstantesPublication.CHAMP_IPNS_ID] = ipns_id
                set_ops[ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE] = ipns_cle_chiffree
            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: type_configuration,
            }
            ops = {
                '$set': set_ops,
                '$setOnInsert': set_on_insert
            }
            collection_ressources.update_one(filtre, ops, upsert=True)

    def identifier_ressources_fichiers(self, site_id: str = None):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre_res = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesPublication.LIBVAL_SECTION_PAGE,
                ConstantesPublication.LIBVAL_SECTION_FICHIERS,
                ConstantesPublication.LIBVAL_SECTION_ALBUM,
                ConstantesPublication.LIBVAL_SECTION_FORUMS,
            ]},
            # ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
        }

        if site_id is not None:
            filtre_res['site_id'] = site_id

        curseur_ressources = collection_ressources.find(filtre_res)
        uuid_collections = set()
        for res in curseur_ressources:
            # Mettre le flag a True immediatement, evite race condition
            filtre_res_update = {
                ConstantesPublication.CHAMP_SECTION_ID: res[ConstantesPublication.CHAMP_SECTION_ID]
            }
            ops = {
                '$set': {ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True},
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            }
            collection_ressources.update_one(filtre_res_update, ops)

            type_section = res[Constantes.DOCUMENT_INFODOC_LIBELLE]
            section_id = res[ConstantesPublication.CHAMP_SECTION_ID]

            if type_section == ConstantesPublication.LIBVAL_SECTION_PAGE:
                self.maj_ressources_page({ConstantesPublication.CHAMP_SECTION_ID: section_id})
            elif type_section in [ConstantesPublication.LIBVAL_SECTION_FICHIERS, ConstantesPublication.LIBVAL_SECTION_ALBUM, ConstantesPublication.LIBVAL_SECTION_FORUMS]:
                uuids = self.maj_ressource_avec_fichiers(section_id)
                uuid_collections.update(uuids)

        # Declencher les processus de synchronisation de collections
        for uuid_collection in uuid_collections:
            processus = "millegrilles_util_PublicationRessources:ProcessusPublierCollectionGrosFichiers"
            params = {
                'uuid_collection': uuid_collection,
                'continuer_publication': True,
            }
            self.__cascade.demarrer_processus(processus, params)

    def maj_ressource_avec_fichiers(self, section_id) -> list:
        """
        Insere ou maj les collections_fichiers associes a des sections (fichiers ou albums)
        :param section_id:
        :return: Liste des uuid de collection
        """
        collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)

        filtre_section = {ConstantesPublication.CHAMP_SECTION_ID: section_id}
        doc_section = collection_sections.find_one(filtre_section)

        # Note : les uuid de forums correspondent aussi au uuid de la collection grosfichiers de ce forum
        collection_uuids = doc_section.get('collections') or doc_section.get('liste_forums') or list()
        site_id = doc_section[ConstantesPublication.CHAMP_SITE_ID]
        site = self.__cascade.get_site(site_id)
        liste_cdns = site[ConstantesPublication.CHAMP_LISTE_CDNS]
        date_courante = datetime.datetime.utcnow()

        set_collection_uuids = set()

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        for collection_uuid in collection_uuids:
            # Conserver le uuid pour generer les processus de synchronisation
            set_collection_uuids.add(collection_uuid)

            # Trouver les collections
            filtre_res_collfichiers = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                'uuid': collection_uuid,
            }
            set_on_insert = {
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,
            }
            add_to_set = {
                ConstantesPublication.CHAMP_LISTE_SITES: {'$each': [site_id]},
            }
            set_ops = {
                ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
            }

            res_coll_fichiers = collection_ressources.find_one(filtre_res_collfichiers) or dict()
            try:
                distribution_complete = res_coll_fichiers[ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE]
            except KeyError:
                distribution_complete = list()

            for cdn_id in liste_cdns:
                if cdn_id not in distribution_complete:
                    set_ops[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id] = False
            set_on_insert.update(filtre_res_collfichiers)
            ops = {
                # '$set': set_ops,
                '$addToSet': add_to_set,
                '$setOnInsert': set_on_insert,
            }
            if set_ops is not None:
                ops['$set'] = set_ops

            collection_ressources.update_one(filtre_res_collfichiers, ops, upsert=True)

        return list(set_collection_uuids)

    def maj_ressource_collection_fichiers(self, info_collection: dict, liste_fichiers: list):
        contenu = {
            ConstantesPublication.CHAMP_TYPE_SECTION: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
        }
        contenu.update(info_collection)
        contenu['fichiers'] = liste_fichiers
        uuid_collection = info_collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        set_fuuids = set()
        thumbnails_chiffres = dict()
        for f in liste_fichiers:
            mimetype = f.get('mimetype') or 'application/stream'
            mimetype_base = mimetype.split('/')[0]

            version_courante = f['version_courante']
            fuuid_v_courante = version_courante['fuuid']
            image_animee = version_courante.get('anime') or False

            fuuids_fichier = list()

            # Recuperer toutes les images
            images = version_courante.get('images')
            if images is not None:
                for value in images.values():
                    if value.get('data_chiffre') is None:
                        # Ce n'est pas une image inline (chiffree)
                        fuuid_image = value['hachage']
                        fuuids_fichier.append(fuuid_image)
                    else:
                        info_thumbnail = value.copy()
                        info_thumbnail['fuuid_fichier'] = fuuid_v_courante
                        # Indexer par hachage du thumbnail - utilise pour dechiffrage
                        thumbnails_chiffres[value['hachage']] = info_thumbnail

            # Recuperer differents formats videos
            videos = version_courante.get('video')
            if videos is not None:
                for value in videos.values():
                    fuuid_image = value['hachage']
                    fuuids_fichier.append(fuuid_image)

            # fuuids_fichier = f.get('fuuids').copy()
            if mimetype_base not in ['video', 'image'] or image_animee is True:
                # On n'a pas un format multimedia (ou on a GIF animee)
                fuuids_fichier.append(fuuid_v_courante)

            if fuuids_fichier:
                set_fuuids.update(fuuids_fichier)

        # Recuperer toutes les ressources associees a cette collection pour trouver les CID
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre_res_fichiers = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            'fuuid': {'$in': list(set_fuuids)},
            'cid': {'$exists': True}
        }
        projection_fichiers = {'fuuid': True, 'cid': True}
        curseur_fichiers = collection_ressources.find(filtre_res_fichiers, projection=projection_fichiers)
        map_cid = dict()
        for fichier in curseur_fichiers:
            cid = fichier['cid']
            fuuid = fichier['fuuid']
            map_cid[fuuid] = cid

        # Creer les entrees manquantes de fichiers  # ATTENTION, potentiel boucle (flag maj_section=False important)
        fuuids_dict = dict()
        fuuids_complets = dict()
        flag_public = info_collection.get('securite') == Constantes.SECURITE_PUBLIC
        for f in liste_fichiers:
            for fuuid in f['fuuids']:
                fuuids_complets[fuuid] = f  # Conserver pour references (e.g. thumbnails)
                if fuuid in set_fuuids:  # S'assurer que c'est un fuuid qu'on veut publier (e.g. pas un thumbnail)
                    fuuids_dict[fuuid] = f
                    try:
                        f['cid'] = map_cid[fuuid]
                    except KeyError:
                        pass  # OK, pas de CID

        self.maj_ressources_fuuids(fuuids_dict, public=flag_public)

        info_fichiers = self.trouver_info_fuuid_fichiers(list(set_fuuids))
        contenu['fuuids'] = info_fichiers

        if len(thumbnails_chiffres) > 0:
            # Dechiffrer tous les thumbnails, remplacer le contenu dans les fichiers
            domaine_action = 'requete.MaitreDesCles.dechiffrage'
            hachage_bytes = [t['hachage'] for t in thumbnails_chiffres.values()]
            requete = {'liste_hachage_bytes': hachage_bytes}
            reponse = self.__cascade.requete_bloquante(domaine_action, requete)

            if reponse['acces'] == '1.permis':
                # Ok, on peut preparer les thumbnails
                for cle, value in reponse['cles'].items():
                    cle_chiffree = value['cle']
                    cle_dechiffree = self.__cascade.dechiffrer_cle(cle_chiffree)
                    decipher = CipherMsg2Dechiffrer(value['iv'], cle_dechiffree, value['tag'])
                    info_thumbnails = thumbnails_chiffres[cle]
                    thumbnail = info_thumbnails['data_chiffre']
                    thumbnail = multibase.decode(thumbnail)
                    thumbnail = decipher.update(thumbnail) + decipher.finalize()
                    thumbnail = multibase.encode('base64', thumbnail).decode('utf-8')

                    # Remplacer le thumbnail chiffre par le thumbnail dechiffre

                    fuuid_fichier = info_thumbnails['fuuid_fichier']
                    info_fichier = fuuids_complets[fuuid_fichier]
                    version_courante = info_fichier['version_courante']
                    images = version_courante['images']
                    thumb_images = images['thumb']
                    del thumb_images['data_chiffre']
                    thumb_images['data'] = thumbnail

        set_ops = {
            'contenu': contenu,
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'uuid': uuid_collection,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'uuid': info_collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC],
        }
        ops = {
            '$set': set_ops,
            '$unset': UNSET_PUBLICATION_RESOURCES,
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        doc_fichiers = collection_ressources.find_one_and_update(filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        return doc_fichiers

    def trouver_info_fuuid_fichiers(self, fuuids: list):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre_fichier = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            'fuuid': {'$in': fuuids},
            # 'cid': {'$exists': True},
        }
        projection_res_fichiers = {'fuuid': True, 'public': True, 'cid': True, 'mimetype': True}
        curseur_fichier = collection_ressources.find(filtre_fichier, projection=projection_res_fichiers)

        fuuids_info = dict()
        for fichier in curseur_fichier:
            fuuid = fichier['fuuid']
            public = fichier.get('public') or False
            fuuids_info[fuuid] = {
                'public': public,
                'mimetype': fichier.get('mimetype')
            }
            cid = fichier.get('cid')
            if cid is not None:
                fuuids_info[fuuid]['cid'] = cid

        return fuuids_info

    def get_fuuids(self, fuuids: list):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre_fichier = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            'fuuid': {'$in': fuuids},
        }
        curseur_fichier = collection_ressources.find(filtre_fichier)
        return [res for res in curseur_fichier]

    def get_collections(self, uuid_collections: list):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre_fichier = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'uuid': {'$in': uuid_collections},
        }
        curseur_collections = collection_ressources.find(filtre_fichier)
        return [res for res in curseur_collections]

    def reset_ressources(self, params: dict):
        """
        Reset l'etat de publication et le contenu de toutes les ressources.
        :return:
        """
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        if params.get('supprimer') is True:
            # On veut supprimer la collection complete
            collection_ressources.remove()
            return {'ok': True}

        unset_opts = {
            ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: True,
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: True,
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
            ConstantesPublication.CHAMP_CONTENU: True,
            # ConstantesPublication.CHAMP_DATE_SIGNATURE: True,
        }
        unset_opts.update(UNSET_PUBLICATION_RESOURCES)
        pull_ops = dict()

        infolib = dict()

        inclure_ressources = params.get('inclure')
        if inclure_ressources:
            infolib['$in'] = inclure_ressources

        ignorer_ressources = params.get('ignorer')
        if ignorer_ressources is not None:
            infolib['$nin'] = ignorer_ressources

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: infolib,
        }

        site_id = params.get('site_id')
        if site_id is not None:
            filtre['site_id'] = site_id

        cdn_id = params.get('cdn_id')
        if cdn_id is not None:
            filtre['distribution_complete'] = {'$all': [cdn_id]}

            # Reset unset_ops
            unset_opts = {
                ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True
            }
            # del unset_opts[ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE]
            # del unset_opts[ConstantesPublication.CHAMP_CONTENU]
            pull_ops[ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE] = cdn_id

        ops = {
            '$unset': unset_opts,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        if len(pull_ops) > 0:
            ops['$pull'] = pull_ops

        resultat = collection_ressources.update_many(filtre, ops)

        return resultat.matched_count

    def sauvegarder_contenu_gzip(self, doc_pub, filtre_res, enveloppes_rechiffrage=None):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        contenu = doc_pub['contenu']

        if enveloppes_rechiffrage is not None:
            # Preparer un identificateur de document pour la cle
            identificateurs_document = {
                Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: 'Publication',
                'collection': 'ressource',
                'type': doc_pub[Constantes.DOCUMENT_INFODOC_LIBELLE],
                Constantes.DOCUMENT_INFODOC_SECURITE: Constantes.SECURITE_PRIVE,
            }

            contenu_maj = dict()

            champs_id = ('uuid', 'section_id', 'site_id')
            for type_id in champs_id:
                if doc_pub.get(type_id):
                    identificateurs_document[type_id] = doc_pub[type_id]
                    contenu_maj[type_id] = doc_pub[type_id]

            # Generer une cle et chiffrer le contenu
            contenu_chiffre, hachage_bytes = self.chiffrer_contenu(contenu, enveloppes_rechiffrage, identificateurs_document)

            # Override du contenu
            contenu_maj['contenu_chiffre'] = contenu_chiffre
            contenu_maj['hachage_bytes'] = hachage_bytes
            try:
                contenu_maj[ConstantesPublication.CHAMP_TYPE_SECTION] = contenu[ConstantesPublication.CHAMP_TYPE_SECTION]
            except KeyError:
                pass  # OK
            contenu = contenu_maj

        contenu_signe = self.__cascade.generateur_transactions.preparer_enveloppe(
            contenu, 'Publication', ajouter_certificats=True)
        contenu_gzippe = self.preparer_json_gzip(contenu_signe)

        # Conserver contenu pour la ressource
        ops = {
            '$set': {
                'contenu_gzip': contenu_gzippe,
                'contenu_signe': contenu_signe
            },
            '$unset': {'distribution_public_complete': True, 'distribution_complete': True},
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
                ConstantesPublication.CHAMP_DATE_SIGNATURE: True,
            },
        }

        doc_res = collection_ressources.find_one_and_update(filtre_res, ops, return_document=ReturnDocument.AFTER)

        return doc_res

    def chiffrer_contenu(self, contenu, enveloppes_rechiffrage, identificateurs_documents):
        """
        Chiffre le contenu, emet la cle pour le MaitreDesCles et retourne le contenu chiffre.
        :param contenu:
        :param enveloppes_rechiffrage:
        :param identificateurs_documents:
        :return: tuple(contenu_chiffre, hachage_bytes)
        """
        json_helper = JSONHelper()

        # Preparer et compresser le contenu a chiffrer
        contenu = json_helper.dict_vers_json(contenu)
        contenu = gzip.compress(contenu)

        cipher = CipherMsg2Chiffrer(encoding_digest='base58btc')
        cipher.start_encrypt()
        contenu = cipher.update(contenu)
        contenu += cipher.finalize()
        hachage_bytes = cipher.digest

        # Chiffrer la cle secrete pour chaque enveloppe
        cles = dict()

        for fingerprint, enveloppe in enveloppes_rechiffrage.items():
            cle_chiffree = cipher.chiffrer_motdepasse_enveloppe(enveloppe)
            cle_chiffree = multibase.encode('base64', cle_chiffree).decode('utf-8')
            cles[fingerprint] = cle_chiffree

        commande_maitrecles = {
            'domaine': 'Publication',
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: identificateurs_documents,
            'format': 'mgs2',
            'cles': cles,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: hachage_bytes,
        }
        commande_maitrecles.update(cipher.get_meta())

        # Transmettre commande de sauvegarde de cle
        self.__cascade.generateur_transactions.transmettre_commande(
            commande_maitrecles, 'commande.MaitreDesCles.' + ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE)

        contenu_chiffre = multibase.encode('base64', contenu).decode('utf-8')

        return contenu_chiffre, hachage_bytes

    def preparer_json_gzip(self, contenu_dict: dict) -> bytes:
        json_helper = JSONHelper()
        contenu = json_helper.dict_vers_json(contenu_dict)
        contenu_gzip = gzip.compress(contenu)
        return contenu_gzip

    def preparer_siteconfig_publication(self, site_id):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            ConstantesPublication.CHAMP_SITE_ID: site_id,
        }
        res_site = collection_ressources.find_one(filtre)

        date_signature = res_site.get(ConstantesPublication.CHAMP_DATE_SIGNATURE)

        if date_signature is None:
            res_site = self.maj_ressources_site({'site_id': site_id})

            # # Changement d'approche, le siteconfig ne sera pas chiffre en mode prive
            # # Les seules informations qui pourraient etre chiffrees sont le titre et info des sections
            # # L'info des CDN et socket.io doivent etre disponibles meme avant enregistrement.
            # securite_site = res_site[ConstantesPublication.CHAMP_CONTENU].get(Constantes.DOCUMENT_INFODOC_SECURITE)
            # if securite_site == Constantes.SECURITE_PRIVE:
            #     # On doit chiffrer le contenu du site
            #     enveloppes_rechiffrage = self.preparer_enveloppes_rechiffrage()
            # else:
            #     enveloppes_rechiffrage = None
            # res_site = self.sauvegarder_contenu_gzip(res_site, filtre, enveloppes_rechiffrage)

            res_site = self.sauvegarder_contenu_gzip(res_site, filtre)

        return res_site

        # # Ajouter info de configuraiton du cdn et signer
        # contenu_siteconfig['cdn_id_local'] = cdn_id
        # contenu_siteconfig = self.generateur_transactions.preparer_enveloppe(
        #     contenu_siteconfig, 'Publication.siteconfig', ajouter_certificats=True)
        #
        # contenu_gzip = self.preparer_json_gzip(contenu_siteconfig)
        # return contenu_gzip

    def detecter_changement_collection(self, contenu_collection: dict):
        """
        Detecte si le contenu de collection de fichiers est different (ressource collection_fichiers)
        :param contenu_collection: dict {collection, documents} tel que recu de la requete sur GrosFichiers
        :return: True si le parametre est different du contenu_signe de la ressource de collection
        """
        info_collection = contenu_collection['collection']
        liste_documents = contenu_collection['documents']

        uuid_collection = info_collection['uuid']
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        res_collection = collection_ressources.find_one({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'uuid': uuid_collection,
        })
        try:
            contenu_signe = res_collection[ConstantesPublication.CHAMP_CONTENU_SIGNE]
        except (KeyError, TypeError):
            # Contenu jamais publie ou invalide, on va recharger le contenu de la collection
            return True

        try:
            preparation_ressource = res_collection[ConstantesPublication.CHAMP_PREPARATION_RESSOURCES]
            if preparation_ressource is False:
                return True  # On a mis le flag a false, forcer regeneration
        except KeyError:
            return True  # Champ manquant

        # Generer un dict des donnees mutables et verifier si elles ont changees
        fuuids_recus = set()
        for fichier in liste_documents:
            fuuids_recus.update(fichier[ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS])
            fuuids_recus.add(fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE])

        try:
            fuuids_signes = set(contenu_signe['fuuids'].keys())

            fuuids_differents = fuuids_recus ^ fuuids_signes  # Extraire fuuids presents dans une seule liste
            if len(fuuids_differents) > 0:
                # On a une difference entre les listes de fuuids
                return True
        except KeyError:
            self.__logger.warning("Erreur comparaison collection %s, contenu_signe n'a pas de fuuids. Regenerer collection." % uuid_collection)
            return True

        return False

    # def ajouter_site_fichiers(self, uuid_collection, sites):
    #     collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
    #     filtre = {
    #         Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
    #         ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
    #     }
    #     ops = {
    #         '$addToSet': {'sites': {'$each': sites}}
    #     }
    #     collection_ressources.update_one(filtre, ops)

    def preparer_enveloppes_rechiffrage(self):
        certs_maitredescles = self.__cascade.requete_bloquante('MaitreDesCles.' + ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES)

        certificat = '\n'.join(certs_maitredescles['certificat'])
        cert_millegrille = certs_maitredescles['certificat_millegrille']
        certs = [certificat, cert_millegrille]

        enveloppes_rechiffrage = dict()
        for cert in certs:
            enveloppe = EnveloppeCertificat(certificat_pem=cert)
            fp = enveloppe.fingerprint
            enveloppes_rechiffrage[fp] = enveloppe

        return enveloppes_rechiffrage


class GestionnaireCascadePublication:

    def __init__(self, gestionnaire_domaine, contexte):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__gestionnaire_domaine = gestionnaire_domaine

        self.ressources_publication = RessourcesPublication(self)
        self.triggers_publication = TriggersPublication(self)
        self.invalidateur_ressources = InvalidateurRessources(self)
        self.http_publication = HttpPublication(self, contexte.configuration)

    def get_site(self, site_id: str):
        return self.__gestionnaire_domaine.get_site(site_id)

    def commande_publier_upload_datasection(self, params: dict):
        """
        Upload le contenu (gzippe) d'une section
        :param params:
        :return:
        """
        params = params.copy()
        type_section = params['type_section']
        cdn_id = params['cdn_id']
        remote_path = params['remote_path']
        mimetype = params.get('mimetype')
        securite = params.get('securite')

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: type_section
        }
        if type_section == ConstantesPublication.LIBVAL_COLLECTION_FICHIERS:
            filtre['uuid'] = params['uuid_collection']
        elif type_section == ConstantesPublication.LIBVAL_SECTION_PAGE:
            filtre[ConstantesPublication.CHAMP_SECTION_ID] = params[ConstantesPublication.CHAMP_SECTION_ID]
        else:
            msg = 'Type section inconnue: %s' % type_section
            self.__logger.error(msg)
            return {'err': msg}

        params['identificateur_document'] = filtre

        res_data = collection_ressources.find_one(filtre)
        if res_data is None:
            msg = 'Aucune section ne correspond a %s' % str(filtre)
            self.__logger.error(msg)
            return {'err': msg}

        contenu_gzip = res_data.get('contenu_gzip')
        if contenu_gzip is None:
            msg = 'Le contenu gzip de la section n\'est pas pret. Section : %s' % str(filtre)
            self.__logger.error(msg)
            return {'err': msg}

        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        filtre_cdn = {'cdn_id': cdn_id}
        cdn = collection_cdns.find_one(filtre_cdn)
        if cdn is None:
            msg = 'Le CDN "%s" n\'existe pas' % cdn_id
            self.__logger.error(msg)
            return {'err': msg}

        try:
            type_cdn = cdn['type_cdn']
            fp_bytesio = BytesIO(contenu_gzip)
            if type_cdn in ['ipfs', 'ipfs_gateway']:
                # Aucune structure de repertoire, uniquement uploader le fichier
                fichiers = [{'remote_path': 'fichier.bin', 'fp': fp_bytesio, 'mimetype': mimetype}]
                params['fichier_unique'] = True
                self.http_publication.put_publier_repertoire([cdn], fichiers, params)
            elif type_cdn in ['awss3', 'sftp']:
                # Methode simple d'upload de fichier avec structure de repertoire
                fichiers = [{'remote_path': remote_path, 'fp': fp_bytesio, 'mimetype': mimetype}]
                self.http_publication.put_publier_repertoire([cdn], fichiers, params)
            elif type_cdn == 'mq':
                self.triggers_publication.emettre_evenements_downstream(res_data)

                # Rien a faire, on marque la config comme publiee
                self.invalidateur.marquer_ressource_complete(cdn_id, filtre)

                # Continuer publication
                self.generateur_transactions.transmettre_commande(
                    dict(), 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION)
            else:
                # Rien a faire, on marque la config comme publiee
                self.invalidateur.marquer_ressource_complete(cdn_id, filtre)

                # Continuer publication
                self.generateur_transactions.transmettre_commande(
                    dict(), 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION)

        except Exception as e:
            msg = "Erreur publication fichiers %s" % str(params)
            self.__logger.exception(msg)
            return {'err': str(e), 'msg': msg}

        return {'ok': True}

    def commande_publier_upload_siteconfiguration(self, params: dict):
        """
        Upload le contenu (gzippe) de siteconfig
        :param params:
        :return:
        """
        params = params.copy()
        site_id = params[ConstantesPublication.CHAMP_SITE_ID]
        cdn_id = params['cdn_id']
        remote_path = params['remote_path']
        mimetype = params.get('mimetype')
        # securite = params.get('securite')

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            ConstantesPublication.CHAMP_SITE_ID: site_id,
        }
        params['identificateur_document'] = filtre

        res_data = collection_ressources.find_one(filtre)
        if res_data is None:
            msg = 'Aucune section ne correspond a %s' % str(filtre)
            self.__logger.error(msg)
            return {'err': msg}

        date_signature = res_data.get(ConstantesPublication.CHAMP_DATE_SIGNATURE)
        if date_signature is None:
            # res_data = self.ressources_publication.sauvegarder_contenu_gzip(res_data, filtre)
            msg = 'La configuration du site n\'est pas preparee : %s' % str(filtre)
            self.__logger.error(msg)
            return {'err': msg}

        contenu_gzip = res_data[ConstantesPublication.CHAMP_CONTENU_GZIP]

        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        filtre_cdn = {'cdn_id': cdn_id}
        cdn = collection_cdns.find_one(filtre_cdn)
        if cdn is None:
            msg = 'Le CDN "%s" n\'existe pas' % cdn_id
            self.__logger.error(msg)
            return {'err': msg}

        try:
            type_cdn = cdn['type_cdn']
            if type_cdn in ['ipfs', 'ipfs_gateway']:
                # Publier avec le IPNS associe a la section
                self.http_publication.put_publier_fichier_ipns(cdn, res_data, Constantes.SECURITE_PRIVE)
            elif type_cdn in ['awss3', 'sftp']:
                # Methode simple d'upload de fichier avec structure de repertoire
                fp_bytesio = BytesIO(contenu_gzip)
                fichiers = [{'remote_path': remote_path, 'fp': fp_bytesio, 'mimetype': mimetype}]
                self.http_publication.put_publier_repertoire([cdn], fichiers, params)
            elif type_cdn == 'mq':
                self.triggers_publication.emettre_evenements_downstream(res_data)

                # Rien a faire, on marque la config comme publiee
                self.invalidateur.marquer_ressource_complete(cdn_id, filtre)

                # Continuer publication
                self.generateur_transactions.transmettre_commande(
                    dict(), 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION)
            else:
                # Rien a faire, on marque la config comme publiee
                self.invalidateur.marquer_ressource_complete(cdn_id, filtre)

                # Continuer publication
                self.generateur_transactions.transmettre_commande(
                    dict(), 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION)

        except Exception as e:
            msg = "Erreur publication fichiers %s" % str(params)
            self.__logger.exception(msg)
            return {'err': str(e), 'msg': msg}

        return {'ok': True}

    def commande_publier_upload_mapping(self, params: dict):
        """
        Upload le contenu (gzippe) du mapping de tous les sites (index.json.gz)
        :param params:
        :return:
        """
        params = params.copy()
        cdn_id = params['cdn_id']
        remote_path = params['remote_path']
        mimetype = params.get('mimetype')
        # securite = params.get('securite')

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING,
        }
        params['identificateur_document'] = filtre

        res_data = collection_ressources.find_one(filtre)
        if res_data is None:
            msg = 'Aucune section ne correspond a %s' % str(filtre)
            self.__logger.error(msg)
            return {'err': msg}

        date_signature = res_data.get(ConstantesPublication.CHAMP_DATE_SIGNATURE)
        if date_signature is None:
            res_data = self.ressources_publication.sauvegarder_contenu_gzip(res_data, filtre)
        contenu_gzip = res_data[ConstantesPublication.CHAMP_CONTENU_GZIP]

        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        filtre_cdn = {'cdn_id': cdn_id}
        cdn = collection_cdns.find_one(filtre_cdn)
        if cdn is None:
            msg = 'Le CDN "%s" n\'existe pas' % cdn_id
            self.__logger.error(msg)
            return {'err': msg}

        try:
            type_cdn = cdn['type_cdn']
            if type_cdn in ['ipfs', 'ipfs_gateway', 'manuel']:
                # Rien a faire, le mapping est inclus avec le code ou recu via MQ
                self.invalidateur_ressources.marquer_ressource_complete(cdn_id, filtre)
            elif type_cdn == 'mq':
                self.triggers_publication.emettre_evenements_downstream(res_data)

                # Rien a faire, on marque la config comme publiee
                self.invalidateur.marquer_ressource_complete(cdn_id, filtre)
            else:
                # Methode simple d'upload de fichier avec structure de repertoire
                fp_bytesio = BytesIO(contenu_gzip)
                fichiers = [{'remote_path': remote_path, 'fp': fp_bytesio, 'mimetype': mimetype}]
                self.http_publication.put_publier_repertoire([cdn], fichiers, params)
        except Exception as e:
            msg = "Erreur publication fichiers %s" % str(params)
            self.__logger.exception(msg)
            return {'err': str(e), 'msg': msg}

        return {'ok': True}

    def traiter_evenement_publicationfichier(self, params: dict):
        """
        Traite un evenement recu de consignation fichiers durant le processus de publication.
        Permet de continuer la publication.
        :param params:
        :return:
        """

        identificateur_document = params['identificateur_document']
        cdn_ids = params.get('cdn_ids') or list()
        cdn_id_unique = params.get('cdn_id')
        if cdn_id_unique:
            cdn_ids.append(cdn_id_unique)

        # fuuid = params.get('fuuid')
        securite = params.get('securite') or Constantes.SECURITE_PRIVE
        flag_complete = params.get('complete') or False
        err = params.get('err') or False
        current_bytes = params.get('current_bytes')
        total_bytes = params.get('total_bytes')

        cid = params.get('cid')  # Identificateur IPFS

        # Determiner type evenement
        set_ops = dict()
        unset_ops = dict()
        add_to_set = dict()
        date_ops = {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
        }
        for cdn_id in cdn_ids:
            if flag_complete:
                # Publication completee
                unset_ops['distribution_encours.' + cdn_id] = True
                unset_ops['distribution_progres.' + cdn_id] = True
                unset_ops['distribution_erreur.' + cdn_id] = True

                add_to_set['distribution_complete'] = cdn_id
                if cid is not None:
                    set_ops['cid'] = cid
                    date_ops['ipfs_publication'] = True

            elif err is not False:
                # Erreur
                unset_ops['distribution_encours.' + cdn_id] = True
                unset_ops['distribution_progres.' + cdn_id] = True
                set_ops['distribution_erreur.' + cdn_id] = err
            elif current_bytes is not None and total_bytes is not None:
                # Progres
                progres = math.floor(current_bytes * 100 / total_bytes)
                set_ops['distribution_progres.' + cdn_id] = progres

        ops = {
            '$currentDate': date_ops
        }
        if len(set_ops) > 0:
            ops['$set'] = set_ops
        if len(unset_ops) > 0:
            ops['$unset'] = unset_ops
        if len(add_to_set) > 0:
            ops['$addToSet'] = add_to_set

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            # 'fuuid': fuuid,
        }
        filtre.update(identificateur_document)
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        collection_ressources.update_one(filtre, ops)

        self.triggers_publication.emettre_evenements_downstream(params)

        # Voir si on lance un trigger de publication de sections
        # self.trigger_conditionnel_fichiers_completes(params)
        self.continuer_publication()

    def traiter_evenement_maj_fichier(self, params: dict):
        # Verifier si on a une reference au fichier ou une collection avec le fichier
        # collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        # fuuids = params.get('fuuids')

        collection_uuids = params.get('collections') or list()
        self.invalidateur_ressources.invalider_ressources_sections_fichiers(collection_uuids)
        collection_uuids = set(collection_uuids)

        # if fuuids is not None:
        #     filtre_fuuids = {
        #         Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
        #         'fuuid': {'$in': fuuids},
        #     }
        #     curseur_fichiers = collection_ressources.find(filtre_fuuids)
        #     for fichier in curseur_fichiers:
        #         collections_fichier = fichier.get('collections')
        #         if collections_fichier is not None:
        #             collection_uuids.update(collections_fichier)
        #
        # # Verifier les collections presentes (deja dans ressources)
        # filtre_collections_fichiers = {
        #     Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
        #     'uuid': {'$in': list(collection_uuids)}
        # }
        # projection_collections_fichiers = {'uuid': True, 'sites': True}
        # curseur_collections_fichiers = collection_ressources.find(filtre_collections_fichiers, projection=projection_collections_fichiers)

        # for collection_fichiers in curseur_collections_fichiers:
        #     # Declencher processus de maj de la collection
        #     uuid_collection = collection_fichiers['uuid']
        #
        #     # sites = collection_fichiers['sites']
        #     # processus = "millegrilles_domaines_Publication:ProcessusPublierCollectionGrosFichiers"
        #     # for site_id in sites:
        #     #     params = {
        #     #         'uuid_collection': uuid_collection,
        #     #         'site_id': site_id,
        #     #     }
        #     #     self.demarrer_processus(processus, params)

    def trigger_conditionnel_fichiers_completes(self, params: dict):
        """
        Verifie si la publication de tous les fichiers est completee
        Soumet un trigger de publication de sections au besoin
        :return:
        """
        # Determiner le type de message recu
        flag_complete = params.get('complete') or False
        err = params.get('err')
        identificateur_document = params['identificateur_document']

        if err is not None or flag_complete is False:
            # Rien a faire
            return

        fuuid = identificateur_document.get('fuuid')
        section_id = identificateur_document.get('section_id')
        type_section = identificateur_document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)

        prochain_trigger = None
        if fuuid is not None:
            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            }
        elif section_id is not None or type_section in [ConstantesPublication.LIBVAL_COLLECTION_FICHIERS, ConstantesPublication.LIBVAL_SECTION_FORUMS]:
            # C'est une section, on verifie si toutes les sections sont completees
            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                    ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                    ConstantesPublication.LIBVAL_SECTION_PAGE,
                    ConstantesPublication.LIBVAL_SECTION_FORUMS,
                ]}
            }
        else:
            # Rien a verifier
            return

        filtre[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES] = {
            '$exists': True,
            '$ne': dict(),
        }
        aggregation_pipeline = [
            {'$match': filtre},
            {'$count': 'en_cours'},
        ]
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        resultat = collection_ressources.aggregate(aggregation_pipeline)
        compte = 0
        for r in resultat:
            compte = r['en_cours']

        if compte == 0:
            self.__logger.debug("Tous les fichiers sont publies, declencher publication sections")
            self.continuer_publication()

    def preparer_permission_secret(self, secret_chiffre):
        secret_bytes = multibase.decode(secret_chiffre)
        secret_hachage = hacher(secret_bytes, encoding='base58btc')
        permission = {
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES: [secret_hachage],
            'duree': 30 * 60 * 60,  # 30 minutes
            'securite': '3.protege',
            'roles_permis': ['Publication'],
        }
        permission = self.generateur_transactions.preparer_enveloppe(permission)
        return permission

    def continuer_publication(self, params: dict = None):
        """
        Declenche une publication complete
        :param params:
        :return:
        """
        compteur_collections_fichiers = self.triggers_publication.trigger_traitement_collections_fichiers()
        if compteur_collections_fichiers > 0:
            self.__logger.info("Preparation des collections de fichiers, %d collections en traitement" % compteur_collections_fichiers)
            return

        compteur_fichiers_publies = self.triggers_publication.trigger_publication_fichiers()
        if compteur_fichiers_publies > 0:
            self.__logger.info("Trigger publication fichiers, %d fichiers a publier" % compteur_fichiers_publies)
            return

        # Aucuns fichiers publies, on emet le trigger de publication des sections
        compteur_commandes_emises = self.continuer_publication_sections()
        if compteur_commandes_emises > 0:
            self.__logger.info("Trigger publication sections, %d commandes emises" % compteur_commandes_emises)
            return

        # Aucunes sections publiees, on transmet le trigger de publication de configuration du site
        compteur_commandes_emises = self.continuer_publication_configuration()
        if compteur_commandes_emises > 0:
            self.__logger.info("Trigger publication siteconfig et mapping, %d commandes emises" % compteur_commandes_emises)
            return

        # Aucunes sections publiees, on transmet le trigger de publication de configuration du site
        compteur_commandes_emises = self.continuer_publication_webapps()
        self.__logger.info("Trigger publication code des webapps, %d commandes emises" % compteur_commandes_emises)

    def continuer_publier_uploadfichiers(self, liste_res_cdns: list):
        """
        Prepare les sections fichiers (collection de fichiers) et transmet la commande d'upload.
        :param liste_res_cdns:
        :return:
        """
        liste_sites = set()
        for cdn in liste_res_cdns:
            liste_sites.update(cdn['sites'])
        liste_sites = list(liste_sites)

        expiration_distribution = datetime.datetime.utcnow() - datetime.timedelta(minutes=30)

        filtre_fichiers = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'sites': {'$in': liste_sites},
        }

        compteur_commandes_emises = 0

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        curseur_fichiers = collection_ressources.find(filtre_fichiers)
        for col_fichiers in curseur_fichiers:
            uuid_col_fichiers = col_fichiers['uuid']
            filtre_fichiers_maj = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                'uuid': uuid_col_fichiers,
            }
            for cdn in liste_res_cdns:
                cdn_id = cdn[ConstantesPublication.CHAMP_CDN_ID]
                self.invalidateur.marquer_ressource_encours(cdn_id, filtre_fichiers_maj, upsert=True)

            # La collection n'a pas encore ete preparee pour la publication
            # contenu = col_fichiers.get('contenu')
            # if contenu is None:
            uuid_collection = col_fichiers['uuid']
            # Demarrer un processus pour la preparation et la publication
            processus = "millegrilles_util_PublicationRessources:ProcessusPublierCollectionGrosFichiers"
            params = {
                'uuid_collection': uuid_collection,
                'site_ids': liste_sites,
                'cdn_ids': [c['cdn_id'] for c in liste_res_cdns],
                'emettre_commande': True,
            }
            self.demarrer_processus(processus, params)
            # else:
            #     self.emettre_commande_publication_collectionfichiers(cdn_id, col_fichiers, securite)

            compteur_commandes_emises = compteur_commandes_emises + 1

        return compteur_commandes_emises

    def continuer_publication_sections(self):
        """
        Publie les donnes du site (repertoire data/ avec les sections pages et collections de fichiers).
        :return:
        """
        liste_cdns = self.triggers_publication.preparer_sitesparcdn()

        compteurs_commandes_emises = 0

        # Publier collections de fichiers
        # repertoire: data/fichiers
        # Trouver les collections de fichiers publiques ou privees qui ne sont pas deja publies sur ce CDN
        # fichiers_publies = self.continuer_publier_uploadfichiers(liste_cdns)
        # compteurs_commandes_emises = compteurs_commandes_emises + fichiers_publies

        for cdn in liste_cdns:
            cdn_id = cdn['cdn_id']
            liste_sites = cdn['sites']

            for site_id in liste_sites:
                # Publier pages
                # repertoire: data/pages
                pages_publiees = self.triggers_publication.emettre_publier_uploadpages(cdn_id, site_id)
                compteurs_commandes_emises = compteurs_commandes_emises + pages_publiees

                # Publier collections de fichiers (metadata)
                # repertoire: data/fichiers
                collections_publiees = self.triggers_publication.emettre_publier_collectionfichiers(cdn_id)
                compteurs_commandes_emises = compteurs_commandes_emises + collections_publiees

                # Publier forums
                # repertoire: data/forums
                collections_publiees = self.triggers_publication.emettre_publier_forum(cdn_id)
                compteurs_commandes_emises = compteurs_commandes_emises + collections_publiees

        return compteurs_commandes_emises

    def continuer_publication_configuration(self):
        """
        Publie la configuration d'un site
        :return:
        """
        liste_cdns = self.triggers_publication.preparer_sitesparcdn()
        compteur_commandes_emises = 0
        for cdn in liste_cdns:
            cdn_id = cdn['cdn_id']
            liste_sites = cdn['sites']

            # Publier les fichiers de configuration de site
            # fichiers: /index.json et /certificat.pem
            for site_id in liste_sites:
                # self.marquer_ressource_encours(cdn_id, filtre_site)
                commandes_emises = self.triggers_publication.emettre_publier_configuration(cdn_id, site_id)
                compteur_commandes_emises = compteur_commandes_emises + commandes_emises

            compteur = self.triggers_publication.emettre_publier_mapping(cdn_id)
            compteur_commandes_emises = compteur_commandes_emises + compteur

        return compteur_commandes_emises

    def continuer_publication_webapps(self):
        """
        Emet les commandes de publication du code des webapps (vitrine, place)
        :return:
        """
        liste_cdns = self.triggers_publication.preparer_sitesparcdn()

        collection_config = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_WEBAPPS}

        # doc_webapps = collection_config.find_one(filtre) or dict()
        res_webapps = collection_ressources.find_one(filtre) or dict()
        distribution_progres = res_webapps.get(ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES) or dict()
        distribution_complete = res_webapps.get(ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE) or list()

        compteurs_commandes_emises = 0

        # Publier code des applications web
        # repertoire: data/fichiers
        for cdn in liste_cdns:
            cdn_id = cdn['cdn_id']
            # type_cdn = cdn['type_cdn']

            if cdn_id in distribution_complete:
                # Code deja distribue, rien a faire
                continue
            elif distribution_progres.get(cdn_id) is True:
                # Distribution deja en cours
                compteurs_commandes_emises = compteurs_commandes_emises + 1
                continue
            elif distribution_progres.get(cdn_id) is not False:
                self.__logger.warning("Deploiement webapp sur cdn_id:%s, aucun flag en place" % cdn_id)
                continue

            compteur = self.triggers_publication.emettre_publier_webapps(cdn_id)
            compteurs_commandes_emises = compteurs_commandes_emises + compteur

        return compteurs_commandes_emises

    def demarrer_processus(self, processus: str, params: dict):
        self.__gestionnaire_domaine.demarrer_processus(processus, params)

    def requete_bloquante(self, domaine_action: str, params: dict = None):
        return self.__gestionnaire_domaine.requete_bloquante(domaine_action, params)

    @property
    def invalidateur(self) -> InvalidateurRessources:
        return self.invalidateur_ressources

    @property
    def ressources(self) -> RessourcesPublication:
        return self.ressources_publication

    @property
    def triggers(self):
        return self.triggers_publication

    @property
    def document_dao(self):
        return self.__gestionnaire_domaine.document_dao

    @property
    def generateur_transactions(self):
        return self.__gestionnaire_domaine.generateur_transactions

    def dechiffrer_cle(self, cle: str):
        return self.__gestionnaire_domaine.dechiffrer_cle(cle)


class TriggersPublication:

    def __init__(self, cascade: GestionnaireCascadePublication):
        self.__cascade = cascade
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    @property
    def document_dao(self):
        return self.__cascade.document_dao

    @property
    def generateur_transactions(self):
        return self.__cascade.generateur_transactions

    def preparer_sitesparcdn(self, site_id: str = None):
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)

        # Faire la liste de tous les CDNs utilises dans au moins 1 site
        filtre_sites = dict()
        if site_id is not None:
            filtre_sites['site_id'] = site_id

        curseur_sites = collection_sites.find(filtre_sites)

        cdns_associes = set()
        sites_par_cdn_dict = dict()
        for s in curseur_sites:
            cdns = s.get('listeCdn')
            if cdns is not None:
                cdns_associes.update(cdns)
                for cdn in cdns:
                    try:
                        liste_sites = sites_par_cdn_dict[cdn]
                    except KeyError:
                        liste_sites = list()
                        sites_par_cdn_dict[cdn] = liste_sites
                    liste_sites.append(s[ConstantesPublication.CHAMP_SITE_ID])

        cdns_associes = list(cdns_associes)
        # Recuperer la liste de CDNs actifs
        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        filtre = {
            ConstantesPublication.CHAMP_CDN_ID: {'$in': cdns_associes},
            'active': True,
        }
        curseur_cdns = collection_cdns.find(filtre)

        # Preparer la liste des CDN, ajouter tous les sites associes a ce CDN (facilite la preparation des ressources)
        liste_cdns = list()
        for cdn in curseur_cdns:
            cdn_id = cdn['cdn_id']
            cdn['sites'] = sites_par_cdn_dict[cdn_id]
            liste_cdns.append(cdn)

        # Trier les CDNs, IPFS en dernier (le plus lent)
        def extract_type_cdn(cdn):
            type_cdn = cdn['type_cdn']
            if type_cdn in ['ipfs', 'ipfs_gateway']:
                return 'z' + type_cdn
            return 'a' + type_cdn
        liste_cdns.sort(key=extract_type_cdn)

        return liste_cdns

    def demarrer_publication_complete(self, params: dict):
        # Marquer toutes les ressources non publiees comme en cours de publication.
        # La methode continuer_publication() utilise cet etat pour publier les ressources en ordre.
        site_id = params.get('site_id') or None

        # Reset le progres de toutes les ressources - permet de liberer ressources bloquees en progres = true
        self.__cascade.invalidateur.reset_ressources_encours(site_id=site_id)

        # Generer toutes les ressources derivant de siteconfig et sections
        self.__cascade.ressources.trouver_ressources_manquantes(site_id=site_id)

        # Generer les ressources collection_fichiers et le contenu de sections pages pour extraire fichiers (fuuids)
        # Va aussi generer les entrees res fichiers associees aux pages
        self.__cascade.ressources.identifier_ressources_fichiers(site_id=site_id)

        compteur_commandes = 0

        # Traiter les ressources par CDN actif
        liste_cdns = self.preparer_sitesparcdn(site_id=site_id)
        for cdn in liste_cdns:
            type_cdn = cdn[ConstantesPublication.CHAMP_TYPE_CDN]
            if type_cdn in ['hiddenService', 'manuel']:
                continue  # rien a faire pour ces CDNs

            cdn_id = cdn[ConstantesPublication.CHAMP_CDN_ID]
            liste_sites = cdn['sites']

            # Recuperer la liste de ressources qui ne sont pas publies dans tous les CDNs de la liste
            collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
            filtre = {
                '$or': [
                    {'site_id': {'$in': liste_sites}},
                    {'sites': {'$in': liste_sites}},
                    {Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [ConstantesPublication.LIBVAL_WEBAPPS]}}
                ],
                # Sections forums, fichiers et albums ne sont pas publies sous forme de ressources, ils sont
                # inclus dans siteconfig
                Constantes.DOCUMENT_INFODOC_LIBELLE: {'$nin': [
                    ConstantesPublication.LIBVAL_SECTION_FICHIERS,
                    ConstantesPublication.LIBVAL_SECTION_ALBUM,
                    ConstantesPublication.LIBVAL_SECTION_FORUMS,
                ]},
                ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: {'$not': {'$all': [cdn_id]}},
            }
            ops = {
                '$set': {
                    ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
                    'distribution_progres.' + cdn_id: False,
                },
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            }
            resultat = collection_ressources.update_many(filtre, ops)
            compteur_commandes = compteur_commandes + resultat.matched_count

        if params.get('nopublish') is not True:
            self.__cascade.continuer_publication()

        return compteur_commandes

    def trigger_traitement_collections_fichiers(self):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        # Recuperer ressources qui ne sont pas preparees
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'$exists': True},
        }
        curseur_collections_fichiers = collection_ressources.find(filtre)

        compteur_collections = 0
        for collection_fichiers in curseur_collections_fichiers:
            # etat_preparation = collection_fichiers[ConstantesPublication.CHAMP_PREPARATION_RESSOURCES]
            #
            # if etat_preparation is True:
            #     continue  # Rien a faire, collection de fichiers prete

            # Compter ressources qui ne sont pas pretes
            compteur_collections = compteur_collections + 1

            # if etat_preparation is False:
            #     continue  # Rien d'autre a faire
            #
            # uuid_collection = collection_fichiers['uuid']
            # liste_sites = collection_fichiers[ConstantesPublication.CHAMP_LISTE_SITES]
            # filtre_coll_fichiers = {
            #     Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            #     'uuid': uuid_collection
            # }
            # ops = {
            #     '$set': {ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: 'en_cours'},
            #     '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            # }
            # collection_ressources.update_one(filtre_coll_fichiers, ops)
            #
            # processus = "millegrilles_domaines_Publication:ProcessusPublierCollectionGrosFichiers"
            # params = {
            #     'uuid_collection': uuid_collection,
            #     'site_ids': liste_sites,
            #     # 'cdn_id': cdn_id,
            #     'emettre_commande': False,
            #     'continuer_publication': True,
            # }
            # self.__cascade.demarrer_processus(processus, params)

        return compteur_collections

    def trigger_publication_fichiers(self):
        """
        Declenche la publication de tous les fichiers de CDN actifs lie a au moins un site.
        :return:
        """
        liste_cdns = self.preparer_sitesparcdn()

        temps_courant = datetime.datetime.utcnow()
        expiration_distribution_en_cours = temps_courant - datetime.timedelta(minutes=30)

        compteur_fichiers_publies = 0  # Compte le nombre de commandes emises
        for cdn in liste_cdns:
            type_cdn = cdn[ConstantesPublication.CHAMP_TYPE_CDN]
            if type_cdn in ['hiddenService', 'manuel']:
                continue  # rien a faire pour ces CDNs

            cdn_id = cdn[ConstantesPublication.CHAMP_CDN_ID]
            # liste_sites = cdn['sites']

            label_champ_distribution = ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id

            # Recuperer la liste de fichiers qui ne sont pas publies dans tous les CDNs de la liste
            collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
            filtre_fichiers = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
                # 'sites': {'$in': liste_sites},
                label_champ_distribution: {'$exists': True},
                # ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: {'$exists': False},
            }
            curseur_res_fichiers = collection_ressources.find(filtre_fichiers)

            # Creer les commandes de publication (consignation fichiers) pour tous les fichiers/CDN
            for fichier in curseur_res_fichiers:
                # Verifier si la commande a deja ete transmise
                valeur_distribution = fichier[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES][cdn_id]
                distribution_maj = fichier.get(ConstantesPublication.CHAMP_DISTRIBUTION_MAJ) or expiration_distribution_en_cours
                if valeur_distribution is False or (valeur_distribution is True and distribution_maj < expiration_distribution_en_cours):
                    # Transmettre la commande
                    self.emettre_commande_publier_fichier(fichier, cdn)

                # Compter le fichier meme si on n'a pas envoye de commande: il est encore en traitement
                compteur_fichiers_publies = compteur_fichiers_publies + 1

        return compteur_fichiers_publies

    def emettre_evenements_downstream(self, params: dict):
        """
        Emet des evenements de changement sur les echanges appropries
        Utilise pour recevoir les changements sur noeuds prives et publics (update via MQ)
        :param params:
        :return:
        """
        identificateur_document = params.get('identificateur_document')

        if identificateur_document:
            type_document = identificateur_document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
            collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
            doc_ressource = collection_ressources.find_one(identificateur_document)
            contenu_signe = doc_ressource.get(ConstantesPublication.CHAMP_CONTENU_SIGNE)
        else:
            type_document = params.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
            contenu_signe = params.get(ConstantesPublication.CHAMP_CONTENU_SIGNE)

        # message = {
        #     ConstantesPublication.CHAMP_TYPE_EVENEMENT: type_document,
        # }
        if type_document == ConstantesPublication.LIBVAL_COLLECTION_FICHIERS:
            domaine_action = 'evenement.Publication.' + ConstantesPublication.EVENEMENT_CONFIRMATION_MAJ_COLLECTION_FICHIERS
            # message['uuid'] = identificateur_document['uuid']
        elif type_document == ConstantesPublication.LIBVAL_SECTION_PAGE:
            domaine_action = 'evenement.Publication.' + ConstantesPublication.EVENEMENT_CONFIRMATION_MAJ_PAGE
            # message[ConstantesPublication.CHAMP_SECTION_ID] = identificateur_document[ConstantesPublication.CHAMP_SECTION_ID]
        elif type_document == ConstantesPublication.LIBVAL_SITE_CONFIG:
            domaine_action = 'evenement.Publication.' + ConstantesPublication.EVENEMENT_CONFIRMATION_MAJ_SITECONFIG
            # message[ConstantesPublication.CHAMP_SITE_ID] = identificateur_document[ConstantesPublication.CHAMP_SITE_ID]
        elif type_document == ConstantesPublication.LIBVAL_MAPPING:
            domaine_action = 'evenement.Publication.' + ConstantesPublication.EVENEMENT_CONFIRMATION_MAJ_MAPPING
            # message[ConstantesPublication.CHAMP_SITE_ID] = identificateur_document[ConstantesPublication.CHAMP_SITE_ID]
        else:
            # Rien a faire
            return

        if contenu_signe is not None:
            # On a le contenu signe (genere en meme temps que le contenu GZIP)
            self.generateur_transactions.emettre_message(contenu_signe, domaine_action, exchanges=[Constantes.SECURITE_PUBLIC])

    def emettre_commande_publier_fichier(self, res_fichier: dict, cdn_info: dict, no_emit=False):
        """
        Generer la commande publier fichier.
        :param res_fichier:
        :param cdn_info:
        :param no_emit: Si True, n'emet pas la commande
        :return: {'params': commande, 'domaine': domaine_action} ou None si rien a faire
        """

        type_cdn = cdn_info['type_cdn']
        cdn_id = cdn_info['cdn_id']
        fuuid = res_fichier['fuuid']

        self.__logger.debug("Publication sur CDN_ID:%s fichier %s" % (cdn_id, str(fuuid)))

        # Ajouter flag de publication dans la ressource
        filtre_fichier_update = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            'fuuid': fuuid,
        }

        if type_cdn == 'sftp':
            params_commande = self.emettre_commande_publier_fichier_sftp(res_fichier, cdn_info, no_emit)
        elif type_cdn in ['ipfs', 'ipfs_gateway']:
            params_commande = self.emettre_commande_publier_fichier_ipfs(res_fichier, cdn_info, no_emit)
        elif type_cdn == 'awss3':
            params_commande = self.emettre_commande_publier_fichier_awss3(res_fichier, cdn_info, no_emit)
        elif type_cdn == 'mq':
            # Emettre document (surtout utile pour MQ)
            self.__cascade.triggers_publication.emettre_evenements_downstream(res_fichier)

            # Rien a faire
            self.__cascade.invalidateur.marquer_ressource_complete(cdn_id, filtre_fichier_update)

            # Continuer publication
            self.generateur_transactions.transmettre_commande(
                dict(), 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION)
            return
        elif type_cdn in ['hiddenService', 'manuel']:
            # Rien a faire
            self.__cascade.invalidateur.marquer_ressource_complete(cdn_id, filtre_fichier_update)

            # Continuer publication
            self.generateur_transactions.transmettre_commande(
                dict(), 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION)
            return
        else:
            raise Exception("Type cdn non supporte %s" % type_cdn)

        self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre_fichier_update)

        return params_commande

    def emettre_commande_publier_fichier_sftp(self, res_fichier: dict, cdn_info: dict, no_emit=False):
        fuuid = res_fichier['fuuid']
        cdn_id = cdn_info['cdn_id']
        flag_public = res_fichier.get('public') or False
        mimetype = res_fichier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE)

        if flag_public:
            securite = Constantes.SECURITE_PUBLIC
        else:
            securite = Constantes.SECURITE_PRIVE

        params = {
            'fuuid': fuuid,
            'cdn_id': cdn_id,
            'host': cdn_info['host'],
            'port': cdn_info['port'],
            'username': cdn_info['username'],
            'basedir': cdn_info['repertoireRemote'],
            'securite': securite,
            'keyType': cdn_info.get('keyType') or 'ed25519',
        }

        if mimetype is not None:
            params[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = mimetype
        elif securite == Constantes.SECURITE_PUBLIC:
            raise Exception("Fichier 1.public a publier sans mimetype")

        domaine = 'commande.fichiers.publierFichierSftp'
        if no_emit is False:
            self.generateur_transactions.transmettre_commande(params, domaine)

        return {'params': params, 'domaine': domaine}

    def emettre_commande_publier_fichier_ipfs(self, res_fichier: dict, cdn_info: dict, no_emit=False):
        fuuid = res_fichier['fuuid']
        cdn_id = cdn_info['cdn_id']
        mimetype = res_fichier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE)

        flag_public = res_fichier.get('public') or False
        if flag_public:
            securite = Constantes.SECURITE_PUBLIC
        else:
            securite = Constantes.SECURITE_PRIVE

        params = {
            'fuuid': fuuid,
            'cdn_id': cdn_id,
            'securite': securite,
        }

        if mimetype is not None:
            params[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = mimetype
        elif securite == Constantes.SECURITE_PUBLIC:
            raise Exception("Fichier 1.public a publier sans mimetype")

        domaine = 'commande.fichiers.publierFichierIpfs'
        if no_emit is False:
            self.generateur_transactions.transmettre_commande(params, domaine)

        return {'params': params, 'domaine': domaine}

    def emettre_commande_publier_fichier_awss3(self, res_fichier: dict, cdn_info: dict, no_emit=False):
        fuuid = res_fichier['fuuid']
        cdn_id = cdn_info['cdn_id']
        mimetype = res_fichier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE)
        uuid_fichier = res_fichier.get('uuid_fichier')

        bucketName = cdn_info['bucketName']
        bucketDirfichier = cdn_info['bucketDirfichier']
        bucketRegion = cdn_info['bucketRegion']
        credentialsAccessKeyId = cdn_info['credentialsAccessKeyId']

        secretAccessKey_chiffre = cdn_info['secretAccessKey_chiffre']
        permission = self.__cascade.preparer_permission_secret(secretAccessKey_chiffre)

        flag_public = res_fichier.get('public') or False
        if flag_public:
            securite = Constantes.SECURITE_PUBLIC
        else:
            securite = Constantes.SECURITE_PRIVE

        params = {
            'fuuid': fuuid,
            'cdn_id': cdn_id,
            'securite': securite,
            'bucketRegion': bucketRegion,
            'credentialsAccessKeyId': credentialsAccessKeyId,
            'secretAccessKey_chiffre': secretAccessKey_chiffre,
            'permission': permission,
            'bucketName': bucketName,
            'bucketDirfichier': bucketDirfichier,
        }
        if mimetype is not None:
            params[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = mimetype
        elif securite == Constantes.SECURITE_PUBLIC:
            raise Exception("Fichier 1.public a publier sans mimetype")

        if uuid_fichier is not None:
            params['uuid'] = uuid_fichier
        domaine = 'commande.fichiers.publierFichierAwsS3'

        if no_emit is False:
            self.generateur_transactions.transmettre_commande(params, domaine)

        return {'params': params, 'domaine': domaine}

    def emettre_publier_uploadpages(self, cdn_id: str, site_id: str):
        """
        Prepare les sections fichiers (collection de fichiers) et transmet la commande d'upload.
        :param cdn_id:
        :param site_id:
        :return:
        """
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        filtre_site = {ConstantesPublication.CHAMP_SITE_ID: site_id}
        doc_site = collection_sites.find_one(filtre_site)
        securite_site = doc_site[Constantes.DOCUMENT_INFODOC_SECURITE]
        label_champ_distribution = ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id

        filtre_pages = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SECTION_PAGE,
            ConstantesPublication.CHAMP_SITE_ID: site_id,
            label_champ_distribution: {'$exists': True},
        }

        compteur_commandes_emises = 0

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        curseur_pages = collection_ressources.find(filtre_pages)
        for res_page in curseur_pages:
            section_id = res_page[ConstantesPublication.CHAMP_SECTION_ID]

            filtre_pages_maj = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SECTION_PAGE,
                ConstantesPublication.CHAMP_SECTION_ID: section_id,
            }
            try:
                valeur_distribution = res_page[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES][cdn_id]
            except KeyError:
                valeur_distribution = None

            if valeur_distribution is False:

                # Generer la page au besoin
                # contenu = doc_page.get('contenu')
                # if contenu is None:
                # Mettre a jour le contenu - s'assure d'avoir tous les CID
                res_page = self.__cascade.ressources.maj_ressources_page({ConstantesPublication.CHAMP_SECTION_ID: section_id})

                if securite_site == Constantes.SECURITE_PRIVE:
                    securite_page = res_page[ConstantesPublication.CHAMP_CONTENU].get(Constantes.DOCUMENT_INFODOC_SECURITE) or securite_site
                else:
                    securite_page = securite_site

                if securite_page == Constantes.SECURITE_PRIVE:
                    enveloppes_rechiffrage = self.__cascade.ressources.preparer_enveloppes_rechiffrage()
                else:
                    enveloppes_rechiffrage = None

                # date_signature = doc_page.get(ConstantesPublication.CHAMP_DATE_SIGNATURE)
                # if date_signature is None:
                # Creer contenu .json.gz
                self.__cascade.ressources.sauvegarder_contenu_gzip(res_page, filtre_pages_maj, enveloppes_rechiffrage)

                # Transmettre la commande
                # Compter le fichier meme si on n'a pas envoye de commande: il est encore en traitement

                # Publier le contenu sur le CDN
                # Upload avec requests via https://fichiers
                commande_publier_section = {
                    'type_section': ConstantesPublication.LIBVAL_SECTION_PAGE,
                    ConstantesPublication.CHAMP_SECTION_ID: section_id,
                    'cdn_id': cdn_id,
                    'securite': securite_site,
                    'remote_path': path.join('data/pages', section_id + '.json.gz'),
                    'mimetype': 'application/json',
                    'content_encoding': 'gzip',  # Header Content-Encoding
                    'max_age': 0,
                }
                domaine_action = 'commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_UPLOAD_DATASECTION
                self.generateur_transactions.transmettre_commande(commande_publier_section, domaine_action)
                self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre_pages_maj)

                compteur_commandes_emises = compteur_commandes_emises + 1

        return compteur_commandes_emises

    def emettre_publier_collectionfichiers(self, cdn_id):
        # collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
        #
        # # Trouver la liste des sections album et fichiers pour ce site (donne list uuid_collection)
        # filtre_collections = {
        #     ConstantesPublication.CHAMP_TYPE_SECTION: {'$in': [
        #         ConstantesPublication.LIBVAL_SECTION_FICHIERS,
        #         ConstantesPublication.LIBVAL_SECTION_ALBUM,
        #     ]},
        #     ConstantesPublication.CHAMP_SITE_ID: site_id,
        # }
        # curseur_sections = collection_sections.find(filtre_collections)
        #
        # uuid_collections = set()
        # for section in curseur_sections:
        #     try:
        #         uuid_collections.update(section[ConstantesPublication.CHAMP_COLLECTIONS])
        #     except (KeyError, AttributeError):
        #         pass  # OK
        #
        # uuid_collections = list(uuid_collections)

        compteur_commandes = 0
        label_champ_distribution = ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        # Charger les collection_fichiers identifiees. Seulement traiter celles qui sont flaggees progres=False
        filtre_collections_fichiers = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            # ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': uuid_collections},
            label_champ_distribution: False,
        }
        curseur_collection_fichiers = collection_ressources.find(filtre_collections_fichiers)
        for res_collection_fichiers in curseur_collection_fichiers:
            uuid_col_fichiers = res_collection_fichiers['uuid']
            contenu = res_collection_fichiers[ConstantesPublication.CHAMP_CONTENU]
            securite_collection = contenu[Constantes.DOCUMENT_INFODOC_SECURITE]

            filtre_fichiers_maj = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                'uuid': uuid_col_fichiers,
            }

            securite_collection = res_collection_fichiers[ConstantesPublication.CHAMP_CONTENU].get(Constantes.DOCUMENT_INFODOC_SECURITE)
            if securite_collection == Constantes.SECURITE_PRIVE:
                enveloppes_rechiffrage = self.__cascade.ressources.preparer_enveloppes_rechiffrage()
            else:
                enveloppes_rechiffrage = None

            date_signature = res_collection_fichiers.get(ConstantesPublication.CHAMP_DATE_SIGNATURE)
            if date_signature is None:
                # Creer contenu .json.gz, contenu_signe
                self.__cascade.ressources.sauvegarder_contenu_gzip(res_collection_fichiers, filtre_fichiers_maj, enveloppes_rechiffrage)

            self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre_fichiers_maj)

            # Marquer tous les fichiers associes a cette collection s'ils ne sont pas deja publies
            # pour ce CDN
            # filtre_fichiers = {
            #     Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            #     ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: {'$not': {'$all': [cdn_id]}},
            #     # ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id: {'exists': False},
            #     'collections': {'$all': [uuid_col_fichiers]}
            #     # 'fuuid': {'$in': liste_fuuids}
            # }
            # self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre_fichiers, many=True, etat=False)

            # Publier le contenu sur le CDN
            # Upload avec requests via https://fichiers
            commande_publier_section = {
                'type_section': ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                'uuid_collection': uuid_col_fichiers,
                'cdn_id': cdn_id,
                'remote_path': path.join('data/fichiers', uuid_col_fichiers + '.json.gz'),
                'mimetype': 'application/json',
                'content_encoding': 'gzip',  # Header Content-Encoding
                'max_age': 0,
                'securite': securite_collection,
            }
            domaine_action = 'commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_UPLOAD_DATASECTION
            self.generateur_transactions.transmettre_commande(commande_publier_section, domaine_action)
            compteur_commandes = compteur_commandes + 1

        return compteur_commandes

    def emettre_publier_forum(self, cdn_id):
        compteur_commandes = 0
        label_champ_distribution = ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        # Charger les collection_fichiers identifiees. Seulement traiter celles qui sont flaggees progres=False
        filtre_collections_fichiers = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SECTION_FORUMS,
            # ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': uuid_collections},
            label_champ_distribution: False,
        }
        curseur_collection_fichiers = collection_ressources.find(filtre_collections_fichiers)
        for res_collection_fichiers in curseur_collection_fichiers:
            uuid_col_fichiers = res_collection_fichiers['uuid']
            contenu = res_collection_fichiers[ConstantesPublication.CHAMP_CONTENU]
            securite_collection = contenu[Constantes.DOCUMENT_INFODOC_SECURITE]

            filtre_fichiers_maj = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                'uuid': uuid_col_fichiers,
            }

            # Pour l'instant, rien a faire. On fait juste marquer complete
            self.__cascade.invalidateur.marquer_ressource_complete(cdn_id, filtre_fichiers_maj)

            # compteur_commandes = compteur_commandes + 1

        return compteur_commandes

    def emettre_publier_configuration(self, cdn_id: str, site_id: str):
        # collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        # filtre_site = {ConstantesPublication.CHAMP_SITE_ID: site_id}
        # doc_site = collection_sites.find_one(filtre_site)
        # securite_site = doc_site[Constantes.DOCUMENT_INFODOC_SECURITE]

        # Trouver tous les sites qui n'ont pas ete publies pour le CDN
        filtre_siteconfig = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            'site_id': site_id,
            ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: {'$not': {'$all': [cdn_id]}},
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        curseur_siteconfig = collection_ressources.find(filtre_siteconfig)
        compteur_commandes = 0
        for res_siteconfig in curseur_siteconfig:
            site_id = res_siteconfig[ConstantesPublication.CHAMP_SITE_ID]
            try:
                etat_distribution = res_siteconfig[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES][cdn_id]
                if etat_distribution is True:
                    # Rien a faire
                    compteur_commandes = compteur_commandes + 1
                    continue
            except KeyError:
                self.__logger.warning("Progres deploiement de site %s sur cdn %s n'est pas conserve correctement" % (site_id, cdn_id))
                continue

            try:
                self.__cascade.ressources.preparer_siteconfig_publication(site_id)

                filtre_section = {
                    Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
                    ConstantesPublication.CHAMP_SITE_ID: site_id,
                }
                self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre_section)

                # Publier le contenu sur le CDN
                # Upload avec requests via https://fichiers
                remote_siteconfig = path.join('data/sites', site_id + '.json.gz')
                commande_publier_siteconfig = {
                    ConstantesPublication.CHAMP_SITE_ID: site_id,
                    'cdn_id': cdn_id,
                    # 'securite': securite_site,
                    'remote_path': remote_siteconfig,
                    'mimetype': 'application/json',
                    'content_encoding': 'gzip',  # Header Content-Encoding
                    'max_age': 0,
                }

                domaine_action = 'commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_UPLOAD_SITECONFIGURATION
                self.generateur_transactions.transmettre_commande(commande_publier_siteconfig, domaine_action)
                compteur_commandes = compteur_commandes + 1
            except Exception:
                self.__logger.exception("Erreur preparation traitement site_id %s" % site_id)

        return compteur_commandes

    def emettre_publier_mapping(self, cdn_id: str):
        filtre_mapping = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING,
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        doc_mapping = collection_ressources.find_one(filtre_mapping)

        try:
            if cdn_id in doc_mapping[ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE]:
                # Distribution completee, rien a faire
                return 0
        except (KeyError, TypeError):
            pass  # OK, on va verifier si le deploiement est en cours

        try:
            etat_distribution = doc_mapping[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES][cdn_id]
            if etat_distribution is True:
                # Rien a faire
                return 1
        except (KeyError, TypeError):
            self.__logger.warning(
                "Progres deploiement de mapping sur cdn %s n'est pas conserve correctement" % cdn_id)

        try:
            doc_res_mapping = self.__cascade.ressources.maj_ressource_mapping()
            self.__cascade.ressources.sauvegarder_contenu_gzip(doc_res_mapping, filtre_mapping)

            filtre_section = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING,
            }
            self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre_section)

            # Publier le contenu sur le CDN
            # Upload avec requests via https://fichiers
            remote_siteconfig = path.join('index.json.gz')
            commande_publier_mapping = {
                'cdn_id': cdn_id,
                'remote_path': remote_siteconfig,
                'mimetype': 'application/json',
                'content_encoding': 'gzip',  # Header Content-Encoding
                'max_age': 0,
            }

            domaine_action = 'commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_UPLOAD_MAPPING
            self.generateur_transactions.transmettre_commande(commande_publier_mapping, domaine_action)

            return 1
        except Exception:
            self.__logger.exception("Erreur preparation traitement mapping")
            return 0

    def emettre_publier_webapps(self, cdn_id: str):
        collection_config = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CONFIGURATION_NOM)
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_WEBAPPS}
        doc_webapps = collection_config.find_one(filtre) or dict()
        res_webapps = collection_ressources.find_one(filtre) or dict()

        try:
            if cdn_id in res_webapps[ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE]:
                # Distribution completee, rien a faire
                return 0
        except (KeyError, TypeError):
            pass  # OK, on va verifier si le deploiement est en cours

        try:
            etat_distribution = res_webapps[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES][cdn_id]
            if etat_distribution is True:
                # Rien a faire
                return 1
        except (KeyError, TypeError):
            self.__logger.warning(
                "Progres deploiement de webapp sur cdn %s n'est pas conserve correctement" % cdn_id)

        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        filtre_cdn = {ConstantesPublication.CHAMP_CDN_ID: cdn_id}
        cdn = collection_cdns.find_one(filtre_cdn)
        type_cdn = cdn['type_cdn']

        if type_cdn in ['ipfs', 'ipfs_gateway']:
            domaine_action = 'commande.fichiers.publierVitrineIpfs'
            ipns_id = doc_webapps.get(ConstantesPublication.CHAMP_IPNS_ID)
            cle_chiffree = doc_webapps.get(ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE)
            if ipns_id is not None and cle_chiffree is not None:
                permission = self.__cascade.preparer_permission_secret(cle_chiffree)
                commande = {
                    'identificateur_document': filtre,
                    'ipns_key': cle_chiffree,
                    'ipns_key_name': 'vitrine',
                    'permission': permission,
                }
                commande.update(cdn)
            else:
                processus = "millegrilles_util_PublicationRessources:ProcessusCreerCleIpnsVitrine"
                params = {'cdn_id': cdn['cdn_id']}
                self.__cascade.demarrer_processus(processus, params)
                return 1
        elif type_cdn == 'sftp':
            domaine_action = 'commande.fichiers.publierVitrineSftp'
            commande = {
                'identificateur_document': filtre,
            }
            commande.update(cdn)
        elif type_cdn == 'awss3':
            permission = self.__cascade.preparer_permission_secret(cdn[ConstantesPublication.CHAMP_AWSS3_SECRETACCESSKEY_CHIFFRE])
            domaine_action = 'commande.fichiers.publierVitrineAwsS3'
            commande = {
                'identificateur_document': filtre,
                'permission': permission,
            }
            commande.update(cdn)
        elif type_cdn == 'mq':
            # Emettre document
            self.__cascade.triggers_publication.emettre_evenements_downstream(res_webapps)

            # Type non supporte ou rien a faire
            self.__cascade.invalidateur.marquer_ressource_complete(cdn_id, filtre)

            # Continuer publication
            self.generateur_transactions.transmettre_commande(
                dict(), 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION)

            return 1
        else:
            # Type non supporte ou rien a faire
            self.__cascade.invalidateur.marquer_ressource_complete(cdn_id, filtre)

            # Continuer publication
            self.generateur_transactions.transmettre_commande(
                dict(), 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION)

            return 0

        self.generateur_transactions.transmettre_commande(commande, domaine_action)
        self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre, upsert=True)

        return 1


class HttpPublication:

    def __init__(self, cascade: GestionnaireCascadePublication, configuration: TransactionConfiguration):
        self.__cascade = cascade
        self.__configuration = configuration

    @property
    def document_dao(self):
        return self.__cascade.document_dao

    def requests_put(self, path_command: str, data, files):

        # Preparer URL de connexion a consignationfichiers
        configuration = self.__configuration
        url_consignationfichiers = 'https://%s:%s/' % (
            configuration.serveur_consignationfichiers_host,
            configuration.serveur_consignationfichiers_port
        )

        r = requests.put(
            url_consignationfichiers + path_command,
            files=files,
            data=data,
            verify=self.__configuration.mq_cafile,
            cert=(self.__configuration.mq_certfile, self.__configuration.mq_keyfile),
            timeout=120000,  # 2 minutes max
        )
        return r

    def put_publier_fichier_ipns(self, cdn: dict, res_data: dict, securite: str):
        ipns_id = res_data.get('ipns_id')
        type_section = res_data[Constantes.DOCUMENT_INFODOC_LIBELLE]
        site_id = res_data.get(ConstantesPublication.CHAMP_SITE_ID)
        identificateur_document = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: type_section,
        }

        if type_section == ConstantesPublication.LIBVAL_COLLECTION_FICHIERS:
            nom_cle = res_data['uuid']
            identificateur_document['uuid'] = nom_cle
        elif type_section == ConstantesPublication.LIBVAL_SITE_CONFIG:
            nom_cle = site_id
            identificateur_document[ConstantesPublication.CHAMP_SITE_ID] = nom_cle
        else:
            nom_cle = res_data['section_id']
            identificateur_document['section_id'] = nom_cle

        if ipns_id is None:
            # Utiliser un processus pour creer la cle et deployer la ressource
            processus = "millegrilles_util_PublicationRessources:ProcessusPublierCleEtFichierIpns"
            params = {
                'identificateur_document': identificateur_document,
                'nom_cle': nom_cle,
                'securite': securite,
                'cdn_id': cdn['cdn_id'],
            }
            self.__cascade.demarrer_processus(processus, params)
        else:
            self.put_fichier_ipns(cdn, identificateur_document, nom_cle, res_data, securite)

    def put_fichier_ipns(self, cdn, identificateur_document, nom_cle, res_data, securite):
        # La cle existe deja. Faire un PUT directement.
        # type_document = identificateur_document[Constantes.DOCUMENT_INFODOC_LIBELLE]
        # if type_document == ConstantesPublication.LIBVAL_SITE_CONFIG:
        #     # Mettre a jour et signer la configuration du site. Ajouter CDN
        #     cdn_id = cdn[ConstantesPublication.CHAMP_CDN_ID]
        #     contenu_gzip = self.preparer_siteconfig_publication(cdn_id, res_data)
        #     fp_bytesio = BytesIO(contenu_gzip)
        # else:
        fp_bytesio = BytesIO(res_data['contenu_gzip'])

        files = list()
        files.append(('files', (nom_cle + '.json.gz', fp_bytesio, 'application/json')))
        # Preparer CDN (json str de liste de CDNs)
        cdn_filtre = dict()
        for key, value in cdn.items():
            if not key.startswith('_'):
                cdn_filtre[key] = value
        cdn_filtre = json.dumps([cdn_filtre])
        cle_chiffree = res_data['ipns_cle_chiffree']
        permission = json.dumps(self.__cascade.preparer_permission_secret(cle_chiffree))
        data = {
            'cdns': cdn_filtre,
            'identificateur_document': json.dumps(identificateur_document),
            'ipns_key': cle_chiffree,
            'ipns_key_name': nom_cle,
            'permission': permission,
            'securite': securite,
        }
        r = self.requests_put('publier/fichierIpns', data, files)
        r.raise_for_status()

    def put_publier_repertoire(self, cdns: list, fichiers: list, params: dict = None):
        """
        Upload vers les CDN une liste de fichiers (supporte structure de repertoires)
        :param cdns: Liste des CDNs ou on deploie les fichiers
        :param fichiers: LIste de fichiers {remote_path, fp, mimetype}
        :param params:
        :return:
        """
        if params is None:
            params = dict()

        max_age = params.get('max_age')
        content_encoding = params.get('content_encoding')
        securite = params.get('securite') or Constantes.SECURITE_PRIVE
        identificateur_document = params.get('identificateur_document')

        files = list()
        for fichier in fichiers:
            remote_path_fichier = fichier['remote_path']
            file_pointer = fichier['fp']
            mimetype_fichier = fichier.get('mimetype') or 'application/octet-stream'
            files.append(('files', (remote_path_fichier, file_pointer, mimetype_fichier)))

            # files.append(
            #     ('files', ('test2/test3/mq.log', open('/home/mathieu/temp/uploadTest/test2/test3/mq.log', 'rb'),
            #                'application/octet-stream')))

        cdn_filtres = list()
        for cdn in cdns:
            cdn_filtre = dict()
            for key, value in cdn.items():
                if not key.startswith('_'):
                    cdn_filtre[key] = value

            type_cdn = cdn['type_cdn']
            if type_cdn == 'awss3':
                secret_chiffre = cdn['secretAccessKey_chiffre']
                cdn_filtre['permission'] = self.__cascade.preparer_permission_secret(secret_chiffre)
            cdn_filtres.append(cdn_filtre)

        data_publier = {
            'cdns': json.dumps(cdn_filtres),
            'securite': securite,
        }
        if max_age is not None:
            data_publier['max_age'] = max_age
        if content_encoding is not None:
            data_publier['content_encoding'] = content_encoding
        if identificateur_document is not None:
            data_publier['identificateur_document'] = json.dumps(identificateur_document)
        if params.get('fichier_unique') is True:
            data_publier['fichier_unique'] = True

        r = self.requests_put('publier/repertoire', data_publier, files)
        r.raise_for_status()


class ProcessusPublierCollectionGrosFichiers(MGProcessus):
    """
    Syncrhonise une collection du domaine GrosFichiers avec une version conservee localement sous Publication.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        params = self.parametres

        # Verifier si la collection existe deja dans ressources
        uuid_collection = params['uuid_collection']
        # res_collection = self.controleur.gestionnaire.get_ressource_collection_fichiers(uuid_collection)

        requete = {
            'uuid': uuid_collection,
        }
        domaine_action = Constantes.ConstantesGrosFichiers.REQUETE_CONTENU_COLLECTION
        self.set_requete(domaine_action, requete)

        # if res_collection is not None and res_collection.get('sites'):
        #     # S'assurer que la collection a les site_ids
        #     self.controleur.gestionnaire.ajouter_site_fichiers(uuid_collection, res_collection['sites'])

        self.set_etape_suivante(ProcessusPublierCollectionGrosFichiers.traiter_maj_collection.__name__)

        return {}

    def traiter_maj_collection(self):

        contenu_collection = self.parametres['reponse'][0]
        uuid_collection = self.parametres['uuid_collection']

        gestionnaire_publication = self.controleur.gestionnaire
        gestionnaire_cascade: GestionnaireCascadePublication = gestionnaire_publication.cascade
        ressources = gestionnaire_cascade.ressources
        invalidateur = gestionnaire_cascade.invalidateur

        if contenu_collection.get('err') is True:
            code_err = contenu_collection.get('code') or 'generique'
            self.__logger.error("Erreur access collection %s, code %s" % (uuid_collection, code_err))
            invalidateur.marquer_ressource_erreur(code_err)
        else:
            changement_detecte = ressources.detecter_changement_collection(contenu_collection)
            if changement_detecte is True:
                info_collection = contenu_collection['collection']
                liste_documents = contenu_collection['documents']

                # Ajouter les fichiers (ressources) manquants. Invalide contenu collection_fichiers.
                ressources.maj_ressource_collection_fichiers(info_collection, liste_documents)

            # Marquer collection_fichiers comme prete. On doit quand meme attendre publication des fichiers avant de
            # generer le contenu (CID, etc.)
            invalidateur.marquer_collection_fichiers_prete(uuid_collection)

        if self.parametres.get('continuer_publication') is True:
            domaine_action = 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION
            self.ajouter_commande_a_transmettre(domaine_action, dict())

        self.set_etape_suivante()  # Termine


class ProcessusPublierFichierIpfs(MGProcessus):

    def initiale(self):
        fuuid = self.parametres['fuuid']
        securite = self.parametres.get('securite') or Constantes.SECURITE_PRIVE
        commande = {
            'securite': securite,
            'fuuid': fuuid,
        }
        domaine_action = 'commande.fichiers.publierFichierIpfs'
        self.ajouter_commande_a_transmettre(domaine_action, commande, blocking=True)
        self.set_etape_suivante(ProcessusPublierFichierIpfs.creer_transaction.__name__)

    def creer_transaction(self):
        reponse = self.parametres['reponse'][0]

        self.set_etape_suivante()  # Termine


class ProcessusPublierCleEtFichierIpns(MGProcessus):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        # Publier la cle ipns
        nom_cle = self.parametres['nom_cle']

        commande_creer_cle = {
            'nom': nom_cle
        }
        domaine_action = 'commande.fichiers.creerCleIpns'
        self.ajouter_commande_a_transmettre(domaine_action, commande_creer_cle, blocking=True)

        self.set_etape_suivante(ProcessusPublierCleEtFichierIpns.publier_fichier.__name__)

    def publier_fichier(self):
        # Sauvegarder la nouvelle cle IPNS
        # "cleId": "k51qzi5uqu5dio45qeftnomadnnezz2w3ni2rjl9h0q4k2eh8up17gzeylip3c",
        # "cle_chiffree": "mdiXefgNip2bHL9TA0mTF2wFge5cYY6G+flglfvphroPNpKNf5Y9linAO20ht1KbA6KGppgW1Xo47QpFguqf5WxEy8tZ3Dkh/88I5Zd6f0C79K7dTsEm9GNmBHAp0/ciwIF1llc+ONdngsjv0UQo9oosaUwBgvWZtP0I/lh9DAT4ereqt0d/2mT/7gUHmZ/vVf1sSn5AGP4xKHjn8a4LWmAcvKTdR4qnx0q87+GECp3l6e+X8+8I2V+23/DkXPnuI9j3RGc5SqGP/9oZPnzUexpi50qexHznW9xvGmW8wAzaafg",
        identificateur_document = self.parametres['identificateur_document']
        reponse_cle = self.parametres['reponse'][0]

        if reponse_cle.get('err'):
            self.__logger.error("Erreur reception cle IPNS : %s" % str(reponse_cle))
            self.set_etape_suivante()  # Termine
            return

        # Creer transaction pour sauvegarder la cle IPNS de maniere permanente
        transaction_cle_ipns = {
            'identificateur_document': identificateur_document,
        }
        transaction_cle_ipns.update(reponse_cle)
        domaine_action = 'Publication.' + ConstantesPublication.TRANSACTION_CLE_IPNS
        self.ajouter_transaction_a_soumettre(domaine_action, transaction_cle_ipns)

        self.controleur.gestionnaire.sauvegarder_cle_ipns(identificateur_document, reponse_cle)

        # Publier fichier
        nom_cle = self.parametres['nom_cle']
        securite = self.parametres['securite']
        cdn_id = self.parametres['cdn_id']
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        res_data = collection_ressources.find_one(identificateur_document)
        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        doc_cdn = collection_cdns.find_one({'cdn_id': cdn_id})

        cascade: GestionnaireCascadePublication = self.controleur.gestionnaire.cascade
        http_publication = cascade.http_publication

        http_publication.put_fichier_ipns(doc_cdn, identificateur_document, nom_cle, res_data, securite)

        self.set_etape_suivante()  # Termine


class ProcessusCreerCleIpnsVitrine(MGProcessus):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        # Publier la cle ipns
        commande_creer_cle = {
            'nom': 'vitrine'
        }
        domaine_action = 'commande.fichiers.creerCleIpns'
        self.ajouter_commande_a_transmettre(domaine_action, commande_creer_cle, blocking=True)

        self.set_etape_suivante(ProcessusCreerCleIpnsVitrine.publier_webapp.__name__)

    def publier_webapp(self):
        # Sauvegarder la nouvelle cle IPNS
        # "cleId": "k51qzi5uqu5dio45qeftnomadnnezz2w3ni2rjl9h0q4k2eh8up17gzeylip3c",
        # "cle_chiffree": "mdiXefgNip2bHL9TA0mTF2wFge5cYY6G+flglfvphroPNpKNf5Y9linAO20ht1KbA6KGppgW1Xo47QpFguqf5WxEy8tZ3Dkh/88I5Zd6f0C79K7dTsEm9GNmBHAp0/ciwIF1llc+ONdngsjv0UQo9oosaUwBgvWZtP0I/lh9DAT4ereqt0d/2mT/7gUHmZ/vVf1sSn5AGP4xKHjn8a4LWmAcvKTdR4qnx0q87+GECp3l6e+X8+8I2V+23/DkXPnuI9j3RGc5SqGP/9oZPnzUexpi50qexHznW9xvGmW8wAzaafg",
        identificateur_document = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_WEBAPPS,
        }
        reponse_cle = self.parametres['reponse'][0]

        if reponse_cle.get('err'):
            self.__logger.error("Erreur reception cle IPNS : %s" % str(reponse_cle))
            self.set_etape_suivante()  # Termine
            return

        # Creer transaction pour sauvegarder la cle IPNS de maniere permanente
        transaction_cle_ipns = {
            'identificateur_document': identificateur_document,
        }
        transaction_cle_ipns.update(reponse_cle)
        domaine_action = 'Publication.' + ConstantesPublication.TRANSACTION_CLE_IPNS
        self.ajouter_transaction_a_soumettre(domaine_action, transaction_cle_ipns)

        self.controleur.gestionnaire.sauvegarder_cle_ipns(identificateur_document, reponse_cle)

        # Publier fichier
        cle_id = reponse_cle['cleId']
        cle_chiffree = reponse_cle['cle_chiffree']
        cdn_id = self.parametres['cdn_id']
        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        doc_cdn = collection_cdns.find_one({'cdn_id': cdn_id})

        cascade: GestionnaireCascadePublication = self.controleur.gestionnaire.cascade

        permission = cascade.preparer_permission_secret(cle_chiffree)
        commande = {
            'identificateur_document': identificateur_document,
            'ipns_key': cle_chiffree,
            'ipns_key_name': 'vitrine',
            'permission': permission,
        }
        commande.update(doc_cdn)

        domaine_action = 'commande.fichiers.publierVitrineIpfs'
        self.ajouter_commande_a_transmettre(domaine_action, commande)

        self.set_etape_suivante()  # Termine


class ProcessusPublierFichierImmediatement(MGProcessus):
    """
    Publie un fichier immediatement sur tous les CDN appropries. Emet une confirmation a la fin.

    Utilise pour publier des ressources dynamiquement (e.g. forum).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        params = self.parametres

        # Recuperer l'entree complete du fichier
        fuuid = params['fuuid']

        requete = {'fuuid': fuuid}
        domaine_action = 'requete.GrosFichiers.' + Constantes.ConstantesGrosFichiers.REQUETE_DOCUMENT_PAR_FUUID
        self.set_requete(domaine_action, requete)

        self.set_etape_suivante(ProcessusPublierFichierImmediatement.publier_fichier.__name__)

    def publier_fichier(self):

        doc_fichier = self.parametres['reponse'][0]
        err = doc_fichier.get('err')
        if err is True:
            code_err = doc_fichier.get('code') or 'generique'
            self.__logger.error("Erreur access fichier %s, code %s" % (self.parametres['fuuid'], code_err))
            self.set_etape_suivante()  # Termine, err
            return {'err': True, 'code': code_err}

        gestionnaire_publication = self.controleur.gestionnaire
        gestionnaire_cascade: GestionnaireCascadePublication = gestionnaire_publication.cascade
        ressources = gestionnaire_cascade.ressources
        triggers = gestionnaire_cascade.triggers

        # Determiner si le fichier est present dans au moins une collection publique (dont forum)
        uuid_collections = doc_fichier['collections']
        res_collections = ressources.get_collections(uuid_collections)

        collections_flags_publics = list()
        set_site_ids = set()  # Liste des sites pour deploiement de la ressources (permet de trouver CDNs)
        for c in res_collections:
            # Conserver la liste des sites de la collection
            set_site_ids.update(c.get('sites'))

            try:
                flag_public = c['contenu']['securite'] == Constantes.SECURITE_PUBLIC
            except KeyError:
                try:
                    flag_public = c['contenu_signe']['securite'] == Constantes.SECURITE_PUBLIC
                except KeyError:
                    try:
                        flag_public = c['contenu_signe']['contenu_chiffre'] is None
                    except KeyError:
                        # Default - public et False
                        flag_public = False
            collections_flags_publics.append(flag_public)

        # Detecter si au moins une collection deja publiee est publique
        flag_public = any(collections_flags_publics)

        # S'assurer que les ressources existent pour tous les fuuid du fichiers
        fuuids_dict = dict()
        info_fuuids = doc_fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_MIMETYPES]
        for fuuid in info_fuuids.keys():
            fuuids_dict[fuuid] = doc_fichier
        ressources.maj_ressources_fuuids(fuuids_dict, public=flag_public)

        # Charger la liste des ressources
        res_fuuids = ressources.get_fuuids(list(info_fuuids.keys()))

        if len(res_fuuids) == 0:
            # Rien a faire
            return {'ok': True, 'len': 0}

        # Charger la liste des site_ids associes aux collections
        sites_par_cdn = triggers.preparer_sitesparcdn()

        # Trouver les CDNs
        cdn_par_id = dict()
        for cdn in sites_par_cdn:
            sites_cdn = set(cdn['sites'])
            if len(sites_cdn.intersection(set_site_ids)) > 0:
                # On a au moins 1 site en commun avec ce CDN
                cdn_par_id[cdn['cdn_id']] = cdn

        # Emettre commandes de publication
        au_moins_1_commande = False
        for res_fichier in res_fuuids:
            for cdn_info in cdn_par_id.values():
                params_commande = triggers.emettre_commande_publier_fichier(res_fichier, cdn_info)
                try:
                    commande = params_commande['params']
                    domaine_action = params_commande['domaine']
                    self.ajouter_commande_a_transmettre(domaine_action, commande, blocking=True)
                    au_moins_1_commande = True
                except TypeError:
                    pass  # Rien a faire (e.g. CDN mq ou manuel)

        if au_moins_1_commande:
            self.set_etape_suivante(ProcessusPublierFichierImmediatement.attendre_publication_complete.__name__)
        else:
            # Rien a faire
            self.set_etape_suivante()  # Termine

        return {
            'fuuids': list(info_fuuids.keys()),
        }

    def attendre_publication_complete(self):
        """
        Etape qui est appelee chaque fois qu'une publication est completee
        :return:
        """
        # Verifier si toutes les publications sont completees.
        fuuids = self.parametres['fuuids']

        gestionnaire_publication = self.controleur.gestionnaire
        gestionnaire_cascade: GestionnaireCascadePublication = gestionnaire_publication.cascade
        ressources = gestionnaire_cascade.ressources

        res_fuuids = ressources.get_fuuids(fuuids)

        etat_complete = list()
        for res_fuuid in res_fuuids:
            try:
                progres = res_fuuid[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES]
                if len(progres) == 0:
                    complete = True
                else:
                    complete = False
            except KeyError:
                # Progres n'est pas present, c'est soit une erreur ou un reset
                complete = True

            etat_complete.append(complete)

        complete = all(etat_complete)

        # Il manque des publications, on se met en attente
        if complete is False:
            self.set_blocking()
            self.set_etape_suivante(ProcessusPublierFichierImmediatement.attendre_publication_complete.__name__)
        else:
            # Complete, il ne reste rien a faire
            self.set_etape_suivante()  # Termine
            return {'ok': True}
