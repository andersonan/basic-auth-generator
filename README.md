#install
```
composer require andersonan/basic-auth-generator
```

#nginx config
```
server {
    ....
    location / {
        ....
        autoindex on;
        auth_basic           "Administrator's Area";
        auth_basic_user_file /$path/.htpasswd;
    }
}
```


#generate .htpasswd file
```
$htpass = new GenerateHtpasswd($path, $domain);
$htpass->filePutHtpasswd([$user => $pass]);
```
htpasswd generate success fully to $path/$domain/.htpass
