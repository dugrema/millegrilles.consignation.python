ma_string = 'ma {good} string'

print(ma_string.format(good='bonne'))

location_base_component = """
            location %s {
                include /etc/nginx.conf.d/component/proxypass.include;
                include /etc/nginx/conf.d/component_base.include;
            }
        """
location_paths = [
    "/coupdoeil",
    "/posteur",
    "/vitrine",
]
locations_content = '\n'.join([location_base_component % loc for loc in location_paths])

print(locations_content)
