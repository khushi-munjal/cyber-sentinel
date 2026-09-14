import { useEffect } from "react";
import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
  useMap,
} from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

const markerIcon = new L.Icon({
  iconUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
  iconRetinaUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
  shadowUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
});

function MapCenter({ latitude, longitude }) {
  const map = useMap();

  useEffect(() => {
    if (
      typeof latitude === "number" &&
      typeof longitude === "number"
    ) {
      map.setView([latitude, longitude], 8);
    }
  }, [latitude, longitude, map]);

  return null;
}

function GeoMap({ geo }) {
  const location = geo?.location;

  if (
    !location ||
    typeof location.latitude !== "number" ||
    typeof location.longitude !== "number"
  ) {
    return (
      <div className="geo-map-empty">
        <strong>No geo intelligence available</strong>
        <span>
          Analyze an email containing usable infrastructure
          intelligence to display the map.
        </span>
      </div>
    );
  }

  const {
    city = "Unknown City",
    region = "Unknown Region",
    country = "Unknown Country",
    latitude,
    longitude,
    isp = "Unknown Infrastructure",
    precision = "City-level intelligence",
    demo_mode = false,
  } = location;

  return (
    <div className="geo-map-wrapper">
      <div className="geo-map-header">
        <div>
          <span className="geo-label">INFRASTRUCTURE LOCATION</span>

          <h3>
            {city}, {region}
          </h3>

          <p>{country}</p>
        </div>

        <div className="geo-mode">
          {demo_mode ? "DEMO INTELLIGENCE" : "LIVE INTELLIGENCE"}
        </div>
      </div>

      <div className="geo-map">
        <MapContainer
          center={[latitude, longitude]}
          zoom={8}
          scrollWheelZoom={true}
          style={{
            height: "100%",
            width: "100%",
          }}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />

          <MapCenter
            latitude={latitude}
            longitude={longitude}
          />

          <Marker
            position={[latitude, longitude]}
            icon={markerIcon}
          >
            <Popup>
              <div>
                <strong>
                  {city}, {region}
                </strong>

                <br />

                <span>{country}</span>

                <br />
                <br />

                <strong>Infrastructure</strong>

                <br />

                <span>{isp}</span>

                <br />
                <br />

                <strong>Precision</strong>

                <br />

                <span>{precision}</span>
              </div>
            </Popup>
          </Marker>
        </MapContainer>
      </div>

      <div className="geo-map-details">
        <div>
          <span>Location</span>
          <strong>
            {city}, {country}
          </strong>
        </div>

        <div>
          <span>Latitude</span>
          <strong>{latitude}</strong>
        </div>

        <div>
          <span>Longitude</span>
          <strong>{longitude}</strong>
        </div>

        <div>
          <span>Source</span>
          <strong>{isp}</strong>
        </div>
      </div>

      <div className="geo-disclaimer">
        Location represents city-level infrastructure intelligence
        and does not claim an exact physical sender location.
      </div>
    </div>
  );
}

export default GeoMap;