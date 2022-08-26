<?xml version="1.0" encoding="UTF-8"?>

<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
   <url>
      <loc>{{service_address}}/</loc>
   </url>
   % for domain in domains:
   <url>
      <loc>{{service_address}}/sites/{{domain}}</loc>
   </url>
   % end
</urlset>
