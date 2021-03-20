ma_string = 'ma {good} string'

print(ma_string.format(good='bonne'))

location_base_component = """
location {location_path} {{
    set $upstream_{appname} {proxypass};
    proxy_pass $upstream_{appname};
    include /etc/nginx/conf.d/component_base_auth.include;
}}
"""

locations_content = location_base_component.format(**{
    'location_path': '/grosfichiers2',
    'proxypass': 'https://grosfichiers2:443',
    'appname': 'grosfichiers2',
    'allo': 'texte dummy'
})

print(locations_content)