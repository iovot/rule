const policy = $resource.link.split("#")[1];
$done({ content: $resource.content.replace(/^\.(.+)$/gm, `host-suffix, $1, ${policy}`) });
