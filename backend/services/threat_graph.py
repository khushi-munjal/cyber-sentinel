def build_threat_graph(
    email_data,
    ioc_result,
    geo_result=None
):
    """
    Build a dynamic threat intelligence graph
    from the analyzed email and extracted IOCs.
    """

    nodes = []
    edges = []

    sender = email_data.get(
        "sender",
        "Unknown Sender"
    )

    subject = email_data.get(
        "subject",
        "No Subject"
    )

    receiver = email_data.get(
        "receiver",
        "Unknown Receiver"
    )

    # -------------------------------------------------
    # EMAIL NODE
    # -------------------------------------------------

    nodes.append({
        "id": "email",
        "label": subject or "Email",
        "type": "email",
        "metadata": {
            "sender": sender,
            "receiver": receiver,
            "subject": subject
        }
    })

    # -------------------------------------------------
    # SENDER NODE
    # -------------------------------------------------

    nodes.append({
        "id": "sender",
        "label": sender,
        "type": "sender"
    })

    edges.append({
        "source": "sender",
        "target": "email",
        "relationship": "sent"
    })

    # -------------------------------------------------
    # RECEIVER NODE
    # -------------------------------------------------

    if receiver:

        nodes.append({
            "id": "receiver",
            "label": receiver,
            "type": "receiver"
        })

        edges.append({
            "source": "email",
            "target": "receiver",
            "relationship": "delivered_to"
        })

    # -------------------------------------------------
    # URL NODES
    # -------------------------------------------------

    urls = ioc_result.get(
        "urls",
        []
    )

    for index, url in enumerate(urls):

        node_id = f"url_{index}"

        nodes.append({
            "id": node_id,
            "label": url,
            "type": "url"
        })

        edges.append({
            "source": "email",
            "target": node_id,
            "relationship": "contains_url"
        })

    # -------------------------------------------------
    # DOMAIN NODES
    # -------------------------------------------------

    domains = ioc_result.get(
        "domains",
        []
    )

    for index, domain in enumerate(domains):

        node_id = f"domain_{index}"

        nodes.append({
            "id": node_id,
            "label": domain,
            "type": "domain"
        })

        edges.append({
            "source": "email",
            "target": node_id,
            "relationship": "references_domain"
        })

    # -------------------------------------------------
    # IP NODES
    # -------------------------------------------------

    ip_addresses = ioc_result.get(
        "ip_addresses",
        []
    )

    for index, ip in enumerate(ip_addresses):

        node_id = f"ip_{index}"

        nodes.append({
            "id": node_id,
            "label": ip,
            "type": "ip"
        })

        edges.append({
            "source": "email",
            "target": node_id,
            "relationship": "references_ip"
        })

    # -------------------------------------------------
    # GEO LOCATION NODE
    # -------------------------------------------------

    if geo_result:

        location = geo_result.get(
            "location"
        )

        if location:

            city = location.get(
                "city",
                "Unknown"
            )

            region = location.get(
                "region",
                ""
            )

            country = location.get(
                "country",
                ""
            )

            location_label = ", ".join(
                part
                for part in [
                    city,
                    region,
                    country
                ]
                if part
            )

            nodes.append({
                "id": "geo",
                "label": location_label,
                "type": "geo",
                "metadata": {
                    "city": city,
                    "region": region,
                    "country": country,
                    "latitude": location.get(
                        "latitude"
                    ),
                    "longitude": location.get(
                        "longitude"
                    ),
                    "isp": location.get(
                        "isp",
                        ""
                    )
                }
            })

            # Connect IP to Geo if IP exists
            if ip_addresses:

                for index in range(
                    len(ip_addresses)
                ):

                    edges.append({
                        "source": f"ip_{index}",
                        "target": "geo",
                        "relationship": "geolocated_to"
                    })

            else:

                edges.append({
                    "source": "email",
                    "target": "geo",
                    "relationship": "geo_intelligence"
                })

    # -------------------------------------------------
    # GRAPH STATISTICS
    # -------------------------------------------------

    node_types = {}

    for node in nodes:

        node_type = node.get(
            "type",
            "unknown"
        )

        node_types[node_type] = (
            node_types.get(
                node_type,
                0
            ) + 1
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "statistics": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_types": node_types
        }
    }