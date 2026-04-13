=====================

Standalone Deployment

=====================




Run FlareInspect as a persistent service on a dedicated server or VM.



Using PM2


----


.. code-block:: bash


    npm install -g pm2

    pm2 start web/server.js --name flareinspect

    pm2 save

    pm2 startup




Using systemd


----


Create ``/etc/systemd/system/flareinspect.service```:



.. code-block:: ini


    [Unit]

    Description=FlareInspect Web Dashboard

    After=network.target


    [Service]

    Type=simple

    User=flareinspect

    WorkingDirectory=/opt/flareinspect

    ExecStart=/usr/bin/node web/server.js

    Environment=HOST=127.0.0.1

    Environment=PORT=3000

    Environment=FLAREINSPECT_API_KEY=your-key

    Restart=on-failure


    [Install]

    WantedBy=multi-user.target




.. code-block:: bash


    sudo systemctl enable flareinspect

    sudo systemctl start flareinspect




Reverse Proxy (nginx)


----


For TLS termination and public access:



.. code-block:: nginx


    server {

        listen 443 ssl;

        server_name flareinspect.example.com;


        ssl_certificate /etc/ssl/certs/flareinspect.crt;

        ssl_certificate_key /etc/ssl/private/flareinspect.key;


        location / {

            proxy_pass http://127.0.0.1:3000;

            proxy_set_header Host $host;

            proxy_set_header X-Real-IP $remote_addr;

            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

            proxy_set_header X-Forwarded-Proto $scheme;

        }

    }




Security Considerations


----


- Bind to`` 127.0.0.1`` and use a reverse proxy for TLS

- Set ``FLAREINSPECT_API_KEY`` for authentication

- Restrict access with firewall rules or VPN

- Assessment artifacts contain sensitive data — protect the storage directory

