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

        return doc_fichiers


class RessourcesPublication:

    def __init__(self, cascade):
        self.__cascade = cascade

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
                contenu = doc_res_site[ConstantesPublication.CHAMP_CONTENU_SIGNE]

                liste_siteconfigs.append(contenu)

                for cdn_site in contenu['cdns']:
                    cdns[cdn_site[ConstantesPublication.CHAMP_CDN_ID]] = cdn_site

                information_site = {
                    ConstantesPublication.CHAMP_SITE_ID: site_id,
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
                ConstantesPublication.LIBVAL_SECTION_FORUM,
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
        fuuids_info, parties_page_ordonnees, site_id = self.formatter_parties_page(section_id)
        fuuids = self.formatter_fuuids_page(fuuids_info)

        contenu = {
            ConstantesPublication.CHAMP_TYPE_SECTION: ConstantesPublication.LIBVAL_SECTION_PAGE,
            ConstantesPublication.CHAMP_SECTION_ID: section_id,
            ConstantesPublication.CHAMP_PARTIES_PAGES: parties_page_ordonnees,
            'fuuids': fuuids,
        }

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
        self.maj_ressources_fuuids(fuuids_info, sites=[site_id], public=flag_public)

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
        if parties_page_ids is not None:
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

        return fuuids_info, parties_page_ordonnees, site_id

    def maj_ressources_fuuids(self, fuuids_info: dict, sites: list = None, public=False, maj_section=True):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        collections_fichiers_uuids = set()
        sites_id = set()
        if sites is not None:
            sites_id.update(sites)

        for fuuid, info in fuuids_info.items():
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

            if sites is not None:
                for s in sites:
                    add_to_set_ops['sites'] = s

            try:
                fuuid_mimetypes = info[ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES]
                set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = fuuid_mimetypes[fuuid]
            except KeyError as ke:
                if fuuid == info['fuuid_v_courante']:
                    set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = info['mimetype']
                else:
                    raise ke

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
            doc_collection_fichiers = collection_ressources.find_one_and_update(
                filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

            sites_coll = doc_collection_fichiers.get('sites')
            if sites_coll is not None:
                sites_id.update(sites_coll)

        # Lancer processus maj des collections de fichiers
        if maj_section:
            # Invalider les ressources fichiers pour publication
            self.__cascade.invalidateur.invalider_ressources_sections_fichiers(list(collections_fichiers_uuids))

            # Publier les ressources fichiers
            for uuid_collection in collections_fichiers_uuids:
                for site_id in sites_id:
                    processus = "millegrilles_domaines_Publication:ProcessusPublierCollectionGrosFichiers"
                    params = {
                        'uuid_collection': uuid_collection,
                        'site_id': site_id,
                    }
                    self.__cascade.demarrer_processus(processus, params)

    def get_ressource_collection_fichiers(self, uuid_collection):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }
        res_collection = collection_ressources.find_one(filtre)
        return res_collection

    def trouver_ressources_manquantes(self):
        """
        Identifie et ajoute toutes les ressources manquantes
        :return:
        """
        date_courante = datetime.datetime.utcnow()
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        # Verifier s'il manque des sites
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        projection_sites = {
            ConstantesPublication.CHAMP_SITE_ID: True,
            ConstantesPublication.CHAMP_IPNS_ID: True,
            ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE: True,
        }
        curseur_sites = collection_sites.find(dict(), projection=projection_sites)
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
        curseur_sections = collection_sections.find(dict())
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

    def identifier_ressources_fichiers(self):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre_res = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesPublication.LIBVAL_SECTION_PAGE,
                ConstantesPublication.LIBVAL_SECTION_FICHIERS,
                ConstantesPublication.LIBVAL_SECTION_ALBUM,
                ConstantesPublication.LIBVAL_SECTION_FORUM,
            ]},
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
        }

        curseur_ressources = collection_ressources.find(filtre_res)
        for res in curseur_ressources:
            # Mettre le flag a True immediatement, evite race condition
            filtre_res_update = {ConstantesPublication.CHAMP_SECTION_ID: res[ConstantesPublication.CHAMP_SECTION_ID]}
            ops = {
                '$set': {ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True},
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            }
            collection_ressources.update_one(filtre_res_update, ops)

            type_section = res[Constantes.DOCUMENT_INFODOC_LIBELLE]
            section_id = res[ConstantesPublication.CHAMP_SECTION_ID]

            if type_section == ConstantesPublication.LIBVAL_SECTION_PAGE:
                self.maj_ressources_page({ConstantesPublication.CHAMP_SECTION_ID: section_id})
            elif type_section in [ConstantesPublication.LIBVAL_SECTION_FICHIERS, ConstantesPublication.LIBVAL_SECTION_ALBUM]:
                self.maj_ressource_avec_fichiers(section_id)

    def maj_ressource_avec_fichiers(self, section_id):
        collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
        filtre_section = {
            ConstantesPublication.CHAMP_SECTION_ID: section_id
        }
        doc_section = collection_sections.find_one(filtre_section)
        collection_uuids = doc_section.get('collections') or list()
        site_id = doc_section[ConstantesPublication.CHAMP_SITE_ID]
        site = self.__cascade.get_site(site_id)
        liste_cdns = site[ConstantesPublication.CHAMP_LISTE_CDNS]
        date_courante = datetime.datetime.utcnow()
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        for collection_uuid in collection_uuids:
            # Trouver les collections
            filtre_res_collfichiers = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                'uuid': collection_uuid,
            }
            set_on_insert = {
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,
                ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: False,
            }
            add_to_set = {
                ConstantesPublication.CHAMP_LISTE_SITES: {'$each': [site_id]},
            }
            set_ops = dict()

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

    def maj_ressource_collection_fichiers(self, site_ids, info_collection: dict, liste_fichiers: list):
        if isinstance(site_ids, str):
            site_ids = [site_ids]

        contenu = {
            ConstantesPublication.CHAMP_TYPE_SECTION: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
        }
        contenu.update(info_collection)
        contenu['fichiers'] = liste_fichiers
        uuid_collection = info_collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        set_fuuids = set()
        for f in liste_fichiers:
            fuuids_fichier = f.get('fuuids')
            if fuuids_fichier:
                set_fuuids.update(fuuids_fichier)

        # Creer les entrees manquantes de fichiers  # ATTENTION, potentiel boucle (flag maj_section=False important)
        fuuids_dict = dict()
        flag_public = info_collection.get('securite') == Constantes.SECURITE_PUBLIC
        for f in liste_fichiers:
            for fuuid in f['fuuids']:
                fuuids_dict[fuuid] = f
        self.maj_ressources_fuuids(fuuids_dict, site_ids, public=flag_public, maj_section=False)

        info_fichiers = self.trouver_info_fuuid_fichiers(list(set_fuuids))
        contenu['fuuids'] = info_fichiers

        # contenu = self.generateur_transactions.preparer_enveloppe(
        #     contenu, 'Publication.fichiers', ajouter_certificats=True)

        set_ops = {
            'contenu': contenu,
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'uuid': uuid_collection,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        add_to_set = {
            'sites': {'$each': site_ids},
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'uuid': info_collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC],
        }
        ops = {
            '$set': set_ops,
            '$unset': UNSET_PUBLICATION_RESOURCES,
            '$setOnInsert': set_on_insert,
            '$addToSet': add_to_set,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
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

    def reset_ressources(self, params: dict):
        """
        Reset l'etat de publication et le contenu de toutes les ressources.
        :return:
        """
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        unset_opts = {
            ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: True,
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True,
        }
        unset_opts.update(UNSET_PUBLICATION_RESOURCES)
        ops = {
            '$unset': unset_opts,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

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

        resultat = collection_ressources.update_many(filtre, ops)

        return resultat.matched_count

    def sauvegarder_contenu_gzip(self, col_fichiers, filtre_res, chiffrer=False):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        contenu = col_fichiers['contenu']
        contenu_signe = self.__cascade.generateur_transactions.preparer_enveloppe(contenu, 'Publication', ajouter_certificats=True)
        contenu_gzippe = self.preparer_json_gzip(contenu_signe, chiffrer)

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

    def preparer_json_gzip(self, contenu_dict: dict, chiffrer=False) -> bytes:
        if chiffrer is True:
            raise NotImplementedError("Chiffrage pas implemente, TODO")
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

        # Generer un dict des donnees mutables et verifier si elles ont changees
        fuuids_recus = set()
        for fichier in liste_documents:
            fuuids_recus.update(fichier[ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS])
            fuuids_recus.add(fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE])
        fuuids_signes = set(contenu_signe['fuuids'].keys())

        fuuids_differents = fuuids_recus ^ fuuids_signes  # Extraire fuuids presents dans une seule liste
        if len(fuuids_differents) > 0:
            # On a une difference entre les listes de fuuids
            return True

        return False

    def ajouter_site_fichiers(self, uuid_collection, sites):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }
        ops = {
            '$addToSet': {'sites': {'$each': sites}}
        }
        collection_ressources.update_one(filtre, ops)


class GestionnaireCascadePublication:

    def __init__(self, gestionnaire_domaine):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__gestionnaire_domaine = gestionnaire_domaine

        self.__ressources_publication = RessourcesPublication(self)
        self.__triggers_publication = TriggersPublication(self)
        self.__invalidateur = InvalidateurRessources(self)
        self.__http_publication = HttpPublication(self, gestionnaire_domaine.contexte.configuration)

    def get_site(self, site_id: str):
        return self.__gestionnaire_domaine.get_site(site_id)

    def commande_publier_upload_datasection(self, params: dict):
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
            else:
                # Methode simple d'upload de fichier avec structure de repertoire
                fichiers = [{'remote_path': remote_path, 'fp': fp_bytesio, 'mimetype': mimetype}]
            self.__http_publication.put_publier_repertoire([cdn], fichiers, params)
        except Exception as e:
            msg = "Erreur publication fichiers %s" % str(params)
            self.__logger.exception(msg)
            return {'err': str(e), 'msg': msg}

        return {'ok': True}

    def commande_publier_upload_siteconfiguration(self, params: dict):
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
            res_data = self.__ressources_publication.sauvegarder_contenu_gzip(res_data, filtre)
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
                self.__http_publication.put_publier_fichier_ipns(cdn, res_data, Constantes.SECURITE_PRIVE)
            else:
                # Methode simple d'upload de fichier avec structure de repertoire
                fp_bytesio = BytesIO(contenu_gzip)
                fichiers = [{'remote_path': remote_path, 'fp': fp_bytesio, 'mimetype': mimetype}]
                self.__http_publication.put_publier_repertoire([cdn], fichiers, params)
        except Exception as e:
            msg = "Erreur publication fichiers %s" % str(params)
            self.__logger.exception(msg)
            return {'err': str(e), 'msg': msg}

        return {'ok': True}

    def commande_publier_upload_mapping(self, params: dict):
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
            res_data = self.__ressources_publication.sauvegarder_contenu_gzip(res_data, filtre)
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
            if type_cdn in ['ipfs', 'ipfs_gateway', 'mq', 'manuel']:
                # Rien a faire, le mapping est inclus avec le code ou recu via MQ
                self.__invalidateur.marquer_ressource_complete(cdn_id, filtre)
            else:
                # Methode simple d'upload de fichier avec structure de repertoire
                fp_bytesio = BytesIO(contenu_gzip)
                fichiers = [{'remote_path': remote_path, 'fp': fp_bytesio, 'mimetype': mimetype}]
                self.__http_publication.put_publier_repertoire([cdn], fichiers, params)
        except Exception as e:
            msg = "Erreur publication fichiers %s" % str(params)
            self.__logger.exception(msg)
            return {'err': str(e), 'msg': msg}

        return {'ok': True}

    def traiter_evenement_publicationfichier(self, params: dict):
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

        self.__triggers_publication.emettre_evenements_downstream(params)

        # Voir si on lance un trigger de publication de sections
        # self.trigger_conditionnel_fichiers_completes(params)
        self.continuer_publication()

    def traiter_evenement_maj_fichier(self, params: dict, routing_key: str):
        # Verifier si on a une reference au fichier ou une collection avec le fichier
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        fuuids = params.get('fuuids')

        collection_uuids = params.get('collections') or list()
        self.__invalidateur.invalider_ressources_sections_fichiers(collection_uuids)
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
        elif section_id is not None or type_section in [ConstantesPublication.LIBVAL_COLLECTION_FICHIERS, ConstantesPublication.LIBVAL_SECTION_FORUM]:
            # C'est une section, on verifie si toutes les sections sont completees
            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                    ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                    ConstantesPublication.LIBVAL_SECTION_PAGE,
                    ConstantesPublication.LIBVAL_SECTION_FORUM,
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
        if params is None:
            params = dict()

        compteur_collections_fichiers = self.__triggers_publication.trigger_traitement_collections_fichiers()
        if compteur_collections_fichiers > 0:
            self.__logger.info("Preparation des collections de fichiers, %d collections en traitement" % compteur_collections_fichiers)
            return

        compteur_fichiers_publies = self.__triggers_publication.trigger_publication_fichiers()
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

    def continuer_publier_uploadfichiers(self, liste_res_cdns: list, securite=Constantes.SECURITE_PUBLIC):
        """
        Prepare les sections fichiers (collection de fichiers) et transmet la commande d'upload.
        :param liste_res_cdns:
        :param securite:
        :return:
        """
        liste_sites = set()
        for cdn in liste_res_cdns:
            liste_sites.update(cdn['sites'])
        liste_sites = list(liste_sites)

        # label_champ_distribution = ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id
        filtre_fichiers = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'sites': {'$in': liste_sites},
            # label_champ_distribution: {'$exists': True},
        }

        compteur_commandes_emises = 0

        expiration_distribution = datetime.datetime.utcnow() - datetime.timedelta(minutes=30)

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        curseur_fichiers = collection_ressources.find(filtre_fichiers)
        for col_fichiers in curseur_fichiers:
            # valeur_distribution = col_fichiers[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES][cdn_id]
            distribution_maj = col_fichiers.get(ConstantesPublication.CHAMP_DISTRIBUTION_MAJ) or expiration_distribution
            # if valeur_distribution is False or (valeur_distribution is True and distribution_maj < expiration_distribution):
            if distribution_maj <= expiration_distribution:
                uuid_col_fichiers = col_fichiers['uuid']
                filtre_fichiers_maj = {
                    Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                    'uuid': uuid_col_fichiers,
                }
                # self.marquer_ressource_encours(cdn_id, filtre_fichiers_maj, upsert=True)

                # La collection n'a pas encore ete preparee pour la publication
                # contenu = col_fichiers.get('contenu')
                # if contenu is None:
                uuid_collection = col_fichiers['uuid']
                # Demarrer un processus pour la preparation et la publication
                processus = "millegrilles_domaines_Publication:ProcessusPublierCollectionGrosFichiers"
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
        liste_cdns = self.__triggers_publication.preparer_sitesparcdn()
        cdn_ids = [c['cdn_id'] for c in liste_cdns]

        compteurs_commandes_emises = 0

        # Publier collections de fichiers
        # repertoire: data/fichiers
        # Trouver les collections de fichiers publiques ou privees qui ne sont pas deja publies sur ce CDN
        fichiers_publies = self.continuer_publier_uploadfichiers(liste_cdns, securite=Constantes.SECURITE_PUBLIC)
        compteurs_commandes_emises = compteurs_commandes_emises + fichiers_publies

        for cdn in liste_cdns:
            cdn_id = cdn['cdn_id']
            liste_sites = cdn['sites']

            # Publier pages
            # repertoire: data/pages
            for site_id in liste_sites:
                pages_publies = self.__triggers_publication.emettre_publier_uploadpages(cdn_id, site_id)
                compteurs_commandes_emises = compteurs_commandes_emises + pages_publies

            # Publier forums
            # repertoire: data/forums

        return compteurs_commandes_emises

    def continuer_publication_configuration(self):
        """
        Publie la configuration d'un site
        :return:
        """
        liste_cdns = self.__triggers_publication.preparer_sitesparcdn()
        compteur_commandes_emises = 0
        for cdn in liste_cdns:
            cdn_id = cdn['cdn_id']
            liste_sites = cdn['sites']

            # Publier les fichiers de configuration de site
            # fichiers: /index.json et /certificat.pem
            for site_id in liste_sites:
                # self.marquer_ressource_encours(cdn_id, filtre_site)
                commandes_emises = self.__triggers_publication.emettre_publier_configuration(cdn_id, site_id)
                compteur_commandes_emises = compteur_commandes_emises + commandes_emises

            compteur = self.__triggers_publication.emettre_publier_mapping(cdn_id)
            compteur_commandes_emises = compteur_commandes_emises + compteur

        return compteur_commandes_emises

    def continuer_publication_webapps(self):
        """
        Emet les commandes de publication du code des webapps (vitrine, place)
        :return:
        """
        liste_cdns = self.__triggers_publication.preparer_sitesparcdn()

        collection_config = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_WEBAPPS}

        doc_webapps = collection_config.find_one(filtre) or dict()
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

            compteur = self.__triggers_publication.emettre_publier_webapps(cdn_id)
            compteurs_commandes_emises = compteurs_commandes_emises + compteur

            # if type_cdn in ['ipfs', 'ipfs_gateway']:
            #     domaine_action = 'commande.fichiers.publierVitrineIpfs'
            #     ipns_id = doc_webapps.get(ConstantesPublication.CHAMP_IPNS_ID)
            #     cle_chiffree = doc_webapps.get(ConstantesPublication.CHAMP_IPNS_CLE_CHIFFREE)
            #     if ipns_id is not None and cle_chiffree is not None:
            #         permission = self.preparer_permission_secretawss3(cle_chiffree)
            #         commande = {
            #             'identificateur_document': filtre,
            #             'ipns_key': cle_chiffree,
            #             'ipns_key_name': 'vitrine',
            #             'permission': permission,
            #         }
            #         commande.update(cdn)
            #     else:
            #         processus = "millegrilles_domaines_Publication:ProcessusCreerCleIpnsVitrine"
            #         params = {'cdn_id': cdn['cdn_id']}
            #         self.demarrer_processus(processus, params)
            #         continue
            # elif type_cdn == 'sftp':
            #     domaine_action = 'commande.fichiers.publierVitrineSftp'
            #     commande = {
            #         'identificateur_document': filtre,
            #     }
            #     commande.update(cdn)
            # elif type_cdn == 'awss3':
            #     permission = self.preparer_permission_secretawss3(cdn[ConstantesPublication.CHAMP_AWSS3_SECRETACCESSKEY_CHIFFRE])
            #     domaine_action = 'commande.fichiers.publierVitrineAwsS3'
            #     commande = {
            #         'identificateur_document': filtre,
            #         'permission': permission,
            #     }
            #     commande.update(cdn)
            # else:
            #     # Type non supporte ou rien a faire
            #     continue

            # self.generateur_transactions.transmettre_commande(commande, domaine_action)
            # self.marquer_ressource_encours(cdn_id, filtre, upsert=True)

            # compteurs_commandes_emises = compteurs_commandes_emises + 1

        return compteurs_commandes_emises

    def demarrer_processus(self, processus: str, params: dict):
        self.__gestionnaire_domaine.demarrer_processus(processus, params)

    @property
    def invalidateur(self) -> InvalidateurRessources:
        return self.__invalidateur

    @property
    def ressources(self) -> RessourcesPublication:
        return self.__ressources_publication

    @property
    def document_dao(self):
        return self.__gestionnaire_domaine.document_dao

    @property
    def generateur_transactions(self):
        return self.__gestionnaire_domaine.generateur_transactions


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

    def preparer_sitesparcdn(self):
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)

        # Faire la liste de tous les CDNs utilises dans au moins 1 site
        curseur_sites = collection_sites.find()

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
        self.__cascade.ressources.trouver_ressources_manquantes()
        self.__cascade.ressources.identifier_ressources_fichiers()

        liste_cdns = self.preparer_sitesparcdn()
        compteur_commandes = 0

        for cdn in liste_cdns:
            type_cdn = cdn[ConstantesPublication.CHAMP_TYPE_CDN]
            if type_cdn in ['hiddenService', 'manuel']:
                continue  # rien a faire pour ces CDNs

            cdn_id = cdn[ConstantesPublication.CHAMP_CDN_ID]
            liste_sites = cdn['sites']

            # Recuperer la liste de fichiers qui ne sont pas publies dans tous les CDNs de la liste
            collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
            filtre = {
                '$or': [
                    {'sites': {'$in': liste_sites}},
                    {'site_id': {'$in': liste_sites}},
                ],
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
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: {'$exists': True},
            ConstantesPublication.CHAMP_LISTE_SITES: {'$exists': True},
        }
        curseur_collections_fichiers = collection_ressources.find(filtre)

        compteur_collections = 0
        for collection_fichiers in curseur_collections_fichiers:
            etat_preparation = collection_fichiers[ConstantesPublication.CHAMP_PREPARATION_RESSOURCES]

            if etat_preparation is True:
                continue  # Rien a faire, collection de fichiers prete

            compteur_collections = compteur_collections + 1

            if etat_preparation == 'en_cours':
                continue  # Rien d'autre a faire

            uuid_collection = collection_fichiers['uuid']
            liste_sites = collection_fichiers[ConstantesPublication.CHAMP_LISTE_SITES]
            filtre_coll_fichiers = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                'uuid': uuid_collection
            }
            ops = {
                '$set': {ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: 'en_cours'},
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            }
            collection_ressources.update_one(filtre_coll_fichiers, ops)

            processus = "millegrilles_domaines_Publication:ProcessusPublierCollectionGrosFichiers"
            params = {
                'uuid_collection': uuid_collection,
                'site_ids': liste_sites,
                # 'cdn_id': cdn_id,
                'emettre_commande': False,
                'continuer_publication': True,
            }
            self.__cascade.demarrer_processus(processus, params)

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
            liste_sites = cdn['sites']

            label_champ_distribution = ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id

            # Recuperer la liste de fichiers qui ne sont pas publies dans tous les CDNs de la liste
            collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
            filtre_fichiers = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
                'sites': {'$in': liste_sites},
                label_champ_distribution: {'$exists': True},
                ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: {'$exists': False},
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
        :param params:
        :return:
        """
        identificateur_document = params.get('identificateur_document')

        if identificateur_document:
            type_document = identificateur_document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
        else:
            type_document = None

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

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        doc_ressource = collection_ressources.find_one(identificateur_document)
        contenu_signe = doc_ressource.get(ConstantesPublication.CHAMP_CONTENU_SIGNE)
        if contenu_signe is not None:
            # On a le contenu signe (genere en meme temps que le contenu GZIP)
            self.generateur_transactions.emettre_message(contenu_signe, domaine_action, exchanges=[Constantes.SECURITE_PUBLIC])

    def emettre_commande_publier_fichier(self, res_fichier: dict, cdn_info: dict):
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
            self.emettre_commande_publier_fichier_sftp(res_fichier, cdn_info)
        elif type_cdn in ['ipfs', 'ipfs_gateway']:
            self.emettre_commande_publier_fichier_ipfs(res_fichier, cdn_info)
        elif type_cdn == 'awss3':
            self.emettre_commande_publier_fichier_awss3(res_fichier, cdn_info)
        elif type_cdn in ['hiddenService', 'manuel', 'mq']:
            # Rien a faire
            self.__cascade.invalidateur.marquer_ressource_complete(cdn_id, filtre_fichier_update)
            return
        else:
            raise Exception("Type cdn non supporte %s" % type_cdn)

        self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre_fichier_update)

    def emettre_commande_publier_fichier_sftp(self, res_fichier: dict, cdn_info: dict):
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
        self.generateur_transactions.transmettre_commande(params, domaine)

    def emettre_commande_publier_fichier_ipfs(self, res_fichier: dict, cdn_info: dict):
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
        self.generateur_transactions.transmettre_commande(params, domaine)

    def emettre_commande_publier_fichier_awss3(self, res_fichier: dict, cdn_info: dict):
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
        self.generateur_transactions.transmettre_commande(params, domaine)

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
        for doc_page in curseur_pages:
            section_id = doc_page[ConstantesPublication.CHAMP_SECTION_ID]

            filtre_pages_maj = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SECTION_PAGE,
                ConstantesPublication.CHAMP_SECTION_ID: section_id,
            }
            try:
                valeur_distribution = doc_page[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES][cdn_id]
            except KeyError:
                valeur_distribution = None

            if valeur_distribution is False:

                # Generer la page au besoin
                contenu = doc_page.get('contenu')
                if contenu is None:
                    # Mettre a jour le contenu
                    doc_page = self.__cascade.ressources.maj_ressources_page({ConstantesPublication.CHAMP_SECTION_ID: section_id})

                date_signature = doc_page.get(ConstantesPublication.CHAMP_DATE_SIGNATURE)
                if date_signature is None:
                    # Creer contenu .json.gz
                    self.__cascade.ressources.sauvegarder_contenu_gzip(doc_page, filtre_pages_maj)

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

    def emettre_publier_collectionfichiers(self, cdn_id, col_fichiers, securite):
        uuid_col_fichiers = col_fichiers['uuid']
        filtre_fichiers_maj = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
            'uuid': uuid_col_fichiers,
        }

        date_signature = col_fichiers.get(ConstantesPublication.CHAMP_DATE_SIGNATURE)
        if date_signature is None:
            # Creer contenu .json.gz, contenu_signe
            self.__cascade.ressources.sauvegarder_contenu_gzip(col_fichiers, filtre_fichiers_maj)

        self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre_fichiers_maj)

        # Marquer tous les fichiers associes a cette collection s'ils ne sont pas deja publies
        # pour ce CDN
        filtre_fichiers = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            ConstantesPublication.CHAMP_DISTRIBUTION_COMPLETE: {'$not': {'$all': [cdn_id]}},
            # ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id: {'exists': False},
            'collections': {'$all': [uuid_col_fichiers]}
            # 'fuuid': {'$in': liste_fuuids}
        }
        self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre_fichiers, many=True, etat=False)

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
            'securite': securite,
        }
        domaine_action = 'commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_UPLOAD_DATASECTION
        self.generateur_transactions.transmettre_commande(commande_publier_section, domaine_action)

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
                    continue
            except KeyError:
                self.__logger.warning("Progres deploiement de site %s sur cdn %s n'est pas conserve correctement" % (site_id, cdn_id))
            try:
                self.__cascade.ressources.preparer_siteconfig_publication(cdn_id, site_id)

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
                processus = "millegrilles_domaines_Publication:ProcessusCreerCleIpnsVitrine"
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
        else:
            # Type non supporte ou rien a faire
            return 0

        self.generateur_transactions.transmettre_commande(commande, domaine_action)
        self.__cascade.invalidateur.marquer_ressource_encours(cdn_id, filtre, upsert=True)

        return 1

        # try:
        #     doc_res_mapping = self.maj_ressource_mapping()
        #     self.sauvegarder_contenu_gzip(doc_res_mapping, filtre_mapping)
        #
        #     filtre_section = {
        #         Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING,
        #     }
        #     self.marquer_ressource_encours(cdn_id, filtre_section)
        #
        #     # Publier le contenu sur le CDN
        #     # Upload avec requests via https://fichiers
        #     remote_siteconfig = path.join('index.json.gz')
        #     commande_publier_mapping = {
        #         'cdn_id': cdn_id,
        #         'remote_path': remote_siteconfig,
        #         'mimetype': 'application/json',
        #         'content_encoding': 'gzip',  # Header Content-Encoding
        #         'max_age': 0,
        #     }
        #
        #     domaine_action = 'commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_UPLOAD_MAPPING
        #     self.generateur_transactions.transmettre_commande(commande_publier_mapping, domaine_action)
        #
        #     return 1
        # except Exception:
        #     self.__logger.exception("Erreur preparation traitement mapping")
        #     return 0


class HttpPublication:

    def __init__(self, cascade: GestionnaireCascadePublication, configuration: TransactionConfiguration):
        self.__cascade = cascade
        self.__configuration = configuration

    @property
    def document_dao(self):
        return self.__cascade.document_dao

    def requests_put(self, path_command: str, data, files):
        r = requests.put(
            'https://fichiers:3021/' + path_command,
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
            processus = "millegrilles_domaines_Publication:ProcessusPublierCleEtFichierIpns"
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
        r = self.requests_put('/publier/fichierIpns', data, files)
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

        r = self.requests_put('/publier/repertoire', data_publier, files)
        r.raise_for_status()


class ProcessusPublierCollectionGrosFichiers(MGProcessus):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        params = self.parametres

        # Verifier si la collection existe deja dans ressources
        uuid_collection = params['uuid_collection']
        res_collection = self.controleur.gestionnaire.get_ressource_collection_fichiers(uuid_collection)

        requete = {'uuid': uuid_collection}
        domaine_action = Constantes.ConstantesGrosFichiers.REQUETE_CONTENU_COLLECTION
        self.set_requete(domaine_action, requete)

        site_id = params.get('site_id')
        site_ids = params.get('site_ids')
        set_site_ids = set()
        if site_id is not None:
            set_site_ids.add(site_id)
        if site_ids is not None:
            set_site_ids.update(site_ids)

        # if res_collection is None:
        #     # Requete vers grosfichiers pour recuperer le contenu de la collection et initialiser tous les fichiers
        #     # requete = {'uuid': uuid_collection}
        #     # domaine_action = Constantes.ConstantesGrosFichiers.REQUETE_CONTENU_COLLECTION
        #     # self.set_requete(domaine_action, requete)
        #     self.set_etape_suivante(ProcessusPublierCollectionGrosFichiers.traiter_nouvelle_collection.__name__)
        # else:
        if res_collection is not None and res_collection.get('sites'):
            # S'assurer que la collection a les site_ids
            self.controleur.gestionnaire.ajouter_site_fichiers(uuid_collection, res_collection['sites'])

        self.set_etape_suivante(ProcessusPublierCollectionGrosFichiers.traiter_maj_collection.__name__)

        return {'site_ids': list(set_site_ids)}

    # def traiter_nouvelle_collection(self):
    #     contenu_collection = self.parametres['reponse'][0]
    #     site_ids = self.parametres['site_ids']
    #
    #     info_collection = contenu_collection['collection']
    #     liste_documents = contenu_collection['documents']
    #
    #     col_fichiers = self.controleur.gestionnaire.creer_ressource_collection_fichiers(site_ids, info_collection, liste_documents)
    #
    #     self.continuer_publication(col_fichiers)
    #
    #     self.set_etape_suivante()  # Termine

    def traiter_maj_collection(self):

        contenu_collection = self.parametres['reponse'][0]
        site_ids = self.parametres['site_ids']
        uuid_collection = self.parametres['uuid_collection']
        cdn_ids = self.parametres.get('cdn_ids') or list()

        changement_detecte = self.controleur.gestionnaire.detecter_changement_collection(contenu_collection)
        if changement_detecte is True:
            info_collection = contenu_collection['collection']
            liste_documents = contenu_collection['documents']

            col_fichiers = self.controleur.gestionnaire.maj_ressource_collection_fichiers(site_ids, info_collection, liste_documents)

            collection_ressources = self.controleur.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
            filtre_coll_fichiers = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_COLLECTION_FICHIERS,
                'uuid': uuid_collection
            }

            set_ops = {ConstantesPublication.CHAMP_PREPARATION_RESSOURCES: True}
            # Ajouter progres = false pour tous les cdn_is
            for cdn_id in cdn_ids:
                label_progres = ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id
                set_ops[label_progres] = False

            ops = {
                '$set': set_ops,
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            }
            collection_ressources.update_one(filtre_coll_fichiers, ops)

            self.continuer_publication(col_fichiers)

        else:
            # Aucun changement a apporter, la version deja signee/gzipee ne change pas
            col_fichiers = self.controleur.gestionnaire.marquer_collection_fichiers_prete(uuid_collection)
            self.continuer_publication(col_fichiers)

            # # Continuer la publication
            # if self.parametres.get('continuer_publication') is True:
            #     domaine_action = 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION
            #     self.ajouter_commande_a_transmettre(domaine_action, dict())

        self.set_etape_suivante()  # Termine

    def continuer_publication(self, col_fichiers):
        if self.parametres.get('emettre_commande') is True:
            try:
                securite = col_fichiers['contenu']['securite']
            except KeyError:
                self.__logger.exception(
                    "Niveau se securite n'est pas inclus dans collection fichiers %s" % self.parametres[
                        'uuid_collection'])
                self.__logger.error("Contenu col fichiers : %s" % str(col_fichiers))
                securite = Constantes.SECURITE_PRIVE

            cdn_id = self.parametres.get('cdn_id')
            cdn_ids = self.parametres.get('cdn_ids')
            cdns = set()
            if cdn_id is not None:
                cdns.add(cdn_id)
            if cdn_ids is not None:
                cdns.update(cdn_ids)

            for cdn_id_l in cdns:
                self.controleur.gestionnaire.emettre_publier_collectionfichiers(cdn_id_l, col_fichiers, securite)
        elif self.parametres.get('continuer_publication') is True:
            domaine_action = 'commande.Publication.' + ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION
            self.ajouter_commande_a_transmettre(domaine_action, dict())


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
        self.controleur.gestionnaire.put_fichier_ipns(doc_cdn, identificateur_document, nom_cle, res_data, securite)

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

        permission = self.controleur.gestionnaire.preparer_permission_secret(cle_chiffree)
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
