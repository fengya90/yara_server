# Yara Server

## How to build


```
cargo build --release  
```

## How to run

Configure the directory structure of the program as follows:

```
➜  ✗ tree 
.
├── config
│   └── config.yaml
├── rules
│   ├── hello.yar
│   └── world.yar
└── yara_server

```

run the command:

```
./yara_server
```

## How to use

### Check the url
```
curl  -X POST -H "Content-Type: application/json" -d '{
    "url": "http://127.0.0.1:8000/test.zip",
    "need_to_unzip":true
}' 'http://127.0.0.1:3000/check/url'
```

### Check the file
```
curl -X POST 'http://127.0.0.1:3000/check/content?need_to_unzip=true'  --data-binary @test.zip
```

### Reload yara rules
```
curl  -X POST  'http://127.0.0.1:3000/manage/reload'
```
