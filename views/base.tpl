<!DOCTYPE html>
<html lang="en">
  <head>
    <title>{{title}} - GPC Support</title>

    % if defined('description'):
    <meta name="Description" content="{{description}}">
    % end
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    % if defined('open_graph') and open_graph:
    <meta property="og:title" content="{{title}}">
    %   if defined('description'):
    <meta property="og:description" content="{{description}}">
    %   end
    % if defined('open_graph_image') and open_graph_image:
    <meta property="og:image" content="https://gpcsup.com/{{open_graph_image}}">
    % else:
    <meta property="og:image" content="https://gpcsup.com/logo.png">
    % end
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="GPC Support">

    <meta name="twitter:site" content="@gpcsup">
    <meta name="twitter:creator" content="@braedon">
    % end

    % if defined('no_index') and no_index:
    <meta name="robots" content="noindex">
    % end
    % canonical_url = get('canonical_url')
    % if canonical_url:
    <link rel="canonical" href="{{canonical_url}}">
    % end

    <link rel="stylesheet" type="text/css" href="https://necolas.github.io/normalize.css/8.0.1/normalize.css" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&family=Roboto+Slab:wght@500&display=swap" rel="stylesheet" crossorigin>
    <link rel="stylesheet" type="text/css" href="/main.css">

    <meta name="theme-color" content="#00885D">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
  </head>
  <body>
% if get('do_indent', True):
%   from gpcsup.misc import indent
{{!indent(base, 4)}}
% else:
{{!base}}
% end

    % if defined('post_scripts'):
    %   for script in post_scripts:
    <script src="/{{script}}.js"></script>
    %   end
    % end
  </body>
</html>
