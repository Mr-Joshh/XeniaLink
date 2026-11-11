# XeniaLink - Xenia Netplay for real Xbox 360 consoles

XeniaLink is a DashLaunch plugin that lets a modded (RGH/JTAG) Xbox 360 play online with
Xenia Canary Netplay users. Games on the console believe they are signed in to Xbox
Live, but all of the "Live" traffic goes to the Xenia Web Services netplay server
instead:

    https://xenia-netplay-2a0298c0e3f4.herokuapp.com/

The console talks to that server directly over HTTPS (built-in TLS), so no PC is needed
while you play.

- **New here and just want to play?** Go to [How to play](#how-to-play).
- **Hosting from your console?** You'll also need [Router setup](#router-setup-port-forwarding).
- **Something not working?** See [Troubleshooting](#troubleshooting).
- **Developer?** See [How it works](#how-it-works).

## Status (2026-11-11)

**Xenia Netplay players have joined matches hosted on the console and played them to the end of the match.**

Supported game: **Star Wars: First Assault** (the Tech Demo Prototype
build with the community's patched `Coalesced_INT.bin`).

| Feature | State |
|---|---|
| Plugin loads on RGH/JTAG (DashLaunch 3.21, with Aurora or the stock dashboard) | Working |
| Offline profile appears signed in to Live (+ Gold) | Working |
| First Assault login (Lucas Online, community backend) | Working |
| Matchmaking on the Xenia server: search, host, join | Working |
| Console's sessions visible to Xenia, and Xenia's sessions visible to the console | Working |
| Xenia player joins a console-hosted match and plays it | Working |
| Built-in HTTPS, no PC needed | Working |
| Console joins a Xenia-hosted match | Untested. The Xenia player needs a connection that accepts incoming traffic (I was only able to use a phone hotspot which does not) |

---

## How to play

This walks through everything from a fresh console to playing a match with Xenia players.

### 1. What you need

**On the console side**
- An RGH or JTAG Xbox 360 with DashLaunch 3.x installed (3.21 is what's tested).
  Aurora, FSD or the stock dashboard all work.
- Star Wars: First Assault, the Tech Demo Prototype build, with the community's
  patched `Coalesced_INT.bin`
- An offline profile or any profile that is not signed in to Live).
- The console connected to the internet

**From XeniaLink** (the release download, or built yourself)
- `XeniaLink.xex`: the plugin.
- `XeniaLink.ini`: its settings file. The defaults already point at the Xenia server.

**To host matches** (strongly recommended. See [Who can host](#who-can-host))
- Access to your router's settings, to forward a few ports to the console.

### 2. Stay off real Xbox Live

XeniaLink makes games *think* you're on Xbox Live. Your console must never actually reach
Microsoft's Xbox Live.

- Use an offline profile. Never sign in to real Xbox Live while XeniaLink is installed.
- In DashLaunch, keep **`liveblock`** and **`livestrong`** turned **on**.
- XeniaLink also blocks games from looking up Xbox Live servers (`block_xbox_live = true`,
  the default). Leave it on.

### 3. Set the console's date and time

The plugin checks the Xenia server's security certificate against the console clock. If the
clock is badly wrong, the plugin falls back to a built-in date, but setting it properly is
better: **System Settings → Clock → Date and Time**, then set today's date and time.

### 4. Copy the files to the console

Copy both files to your hard drive:

| File | Copy to |
|---|---|
| `XeniaLink.xex` | `Hdd:\XeniaLink.xex` |
| `XeniaLink.ini` | `Hdd:\XeniaLink.ini` (must be exactly this path) |

### 5. Add the plugin to DashLaunch

1. Open DashLaunch
2. Under `[Plugins]`, add XeniaLink on a free plugin line, for example
   `plugin2 = Hdd:\XeniaLink.xex`
3. Under `[Settings]`, check that these are on:

   ```ini
   liveblock = true
   livestrong = true
   ```
4. Save

### 6. Reboot

Turn the console fully off and on again so DashLaunch loads the plugin.

### 7. Set up your router (to host)

To host a match, Xenia players on the internet have to be able to reach your console. You can skip this step if you do not plan on hosting.
That needs four port forwards on your router to the console's IP address:

| Port | Protocol |
|---|---|
| 1225 | TCP |
| 8677 | TCP |
| 1000 | UDP |
| 1001 | UDP (Not needed when the console hosts. May matter when Xenia hosts (untested)) |

Full step-by-step instructions are in [Router setup](#router-setup-port-forwarding).

### 8. Play

Start Star Wars: First Assault and search for a game. If everything was set up right you should be good to go

A few seconds after the game starts you should see a notification: `XeniaLink: connected to Xenia server`

| You see | Meaning |
|---|---|
| `XeniaLink: connected to Xenia server` | Everything's fine |
| `XeniaLink: can't reach Xenia server` | The console can't reach the server. Check its internet connection and `api_address` in `XeniaLink.ini` |
| Nothing | DashLaunch didn't load the plugin. Check the `launch.ini` line and the path |

The game re-hosts about every 30 seconds while waiting, so a Xenia player who starts
searching will find you within a few searches.

#### Who can host

| Console player | Xenia player | Works? |
|---|---|---|
| Hosts (ports forwarded) | Joins | Yes |
| Joins | Hosts (their ports forwarded, or UPnP on) | Untested |
| Same home network as the Xenia PC | — | No. Both share one public IP and the router can only forward each port to one device |

The reliable setup today: **the console hosts, and Xenia players join.**

---

## Router setup (port forwarding)

When the console hosts, the Xenia player connects to your console from the internet.
Your router blocks incoming connections by default, so you have to tell it to pass
First Assault's ports to the console. Without this, Xenia finds your session but never
gets in.

### What to set

| Rule name (any) | External port | Internal IP | Internal port | Protocol |
|---|---|---|---|---|
| XeniaLink TCP 1 | 1225 | the console's IP (e.g. `192.168.0.110`) | 1225 | TCP |
| XeniaLink TCP 2 | 8677 | the console's IP | 8677 | TCP |
| XeniaLink UDP 1 | 1000 | the console's IP | 1000 | UDP |
| XeniaLink UDP 2 | 1001 | the console's IP | 1001 | UDP (optional, harmless) |

Using ALL / Both as the protocol for all four rules is fine and the simplest option.

### Step by step (TP-Link routers)

1. **Find the console's IP.** On the console: System Settings → Network Settings →
   your network → *Additional Settings* → *Advanced Settings*, or check the router's
   client list. The examples here use `192.168.0.110`.
2. **Log in to the router.** On a device connected to the home network (Wi-Fi or
   Ethernet), open <http://tplinkwifi.net> or type in your default gateway (e.g. 192.168.0.1) and enter the admin password.
3. **Give the console a fixed IP (only if it changes).** Many routers keep giving the
   console the same IP on their own, and then this step isn't needed. If you notice the
   console's IP changing, hosting stops working because the forwards point at the old address. To stop that, go to
   **Advanced → Network → DHCP Server → Address Reservation → Add**, enter the console's
   MAC address (shown in the console's network settings, or the router's client list) and
   its IP, e.g. `192.168.0.110`, and save.
4. **Add the forwards.** Go to **Advanced → NAT Forwarding → Virtual Servers**. Click *Add* for each row of the table
   above:
   - *Service Type*: any name, e.g. `XeniaLink TCP 1`
   - *External Port*: `1225` (then 8677, 1000, 1001)
   - *Internal IP*: `192.168.0.110`
   - *Internal Port*: same as the external port
   - *Protocol*: `TCP` for 1225/8677, `UDP` for 1000/1001 (or `ALL` for all four)
   - Tick *Enable* and click **Save**.
5. **Turn off UPnP, or clean it up.** Go to **Advanced → NAT Forwarding → UPnP**. If Xenia
   ever ran on a PC on this network, UPnP may have mapped 1225/8677 to that PC, and those
   mappings override your forwards. Either turn UPnP off, or delete any entries for
   1225, 8677, 1000 or 1001 that point at a device other than the console. (Turning it back
   on later is fine; see [Turning UPnP back on](#turning-upnp-back-on).)
6. **Reboot the router.** Go to **System Tools → Reboot** (or the reboot icon, top right).
   This applies the rules and clears old UPnP mappings. If there are no previous UPnP mappings then you shouldn't need to reboot.

Other routers have the same settings under names like *Port Forwarding*, *Virtual
Server*, *NAT* or *Applications & Gaming*.

### Turning UPnP back on

After the forwards work, it's fine to turn UPnP on again (if other things in the house need it).

If you turn it back on:

1. Turn on **Advanced → NAT Forwarding → UPnP**.
2. If you ever run Xenia on a PC at home, check the UPnP list afterwards and delete any
   entries for 1225, 8677, 1000 or 1001 that point at the PC (a router reboot should also
   clears them). Then host from the console again.

If nothing in the house needs UPnP, leaving it off is the simplest choice.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Stuck on "Logging in to Lucas Online" | Usually the community backend is down. Check the log for `xhttp:` errors |
| Start Game never finds anyone | Normal if nobody is hosting, your console will host after a few searches |
| Xenia finds your session but can't join | See [Router setup](#router-setup-port-forwarding). Potential causes: TCP (not UDP) for 1225/8677; check UPnP; reboot the router; check the console's IP hasn't changed |
| Xenia joins, the match starts, then Xenia "lost connection to host" | UDP 1000 isn't forwarded to the console |

---

## How it works

Xenia Netplay lets players play online by replacing Xbox Live with a simple
community server, Xenia Web Services. XeniaLink brings the same idea to a real console:
while a game is running, it quietly redirects the game's "Xbox Live" activity to that
server, so console and Xenia players end up in the same matches.

**What the plugin does while a game is running**

- **Makes the game think you're online.** The game is told your offline profile is signed
  in to Xbox Live with Gold, so its online menus unlock. Nothing ever connects to Microsoft:
  XeniaLink blocks the game from looking up Xbox Live's servers.
- **Sends matchmaking to the Xenia server.** When the game searches for, creates, joins or
  leaves a match, XeniaLink sends that request to Xenia Web Services instead of Xbox Live.
  Xenia uses the same server, which is why the console and Xenia see each other's matches.
- **Lets Xenia players connect.** A normal console only accepts encrypted connections from
  other Xboxes and ignores everything else. Xenia sends ordinary, unencrypted game traffic,
  so XeniaLink switches the game's connections to accept it. Players connect straight to the
  host's internet address, which is why the host needs port forwarding.
- **Handles First Assault's own login.** The game logs in to its community-run server
  (Lucas Online). The console's built-in way of doing that needs Xbox Live, so XeniaLink
  provides it instead.

Only the running game is affected. The dashboard, Aurora and FSD are left alone, and no game
files are changed.

### Ports

| Port | Type | What it's for |
|---|---|---|
| 1225 | TCP | Joining the host's lobby |
| 8677 | TCP | A second lobby connection |
| 1000 | UDP | Game traffic during the match |
| 1001 | UDP | Used by Xenia on its own side; not needed when the console hosts |

Only the host needs these forwarded (see [Router setup](#router-setup-port-forwarding)).
Players who join don't.

### Secure connection to the server (HTTPS and BearSSL)

The Xenia server only accepts modern secure (HTTPS) connections, and the Xbox 360's own
HTTPS support is too old for it. So XeniaLink includes its own:
[BearSSL](https://bearssl.org/), a small open-source security library by Thomas Pornin
(MIT licence; included as `LICENSE-BearSSL.txt` in the release download). It encrypts the
connection and checks the server's certificate, so the console knows it's really talking to
the Xenia server.

- It's only used for the Xenia server. Game traffic between players doesn't go through it.
- The certificate check uses today's date, which is why the console's clock should be set
  ([step 3](#3-set-the-consoles-date-and-time)).
- Connections are kept open between requests, so matchmaking calls are quick (usually
  0.1–0.2 seconds).

## Roadmap

1. ~~Handshake~~ Done
2. ~~Login + matchmaking against the Xenia server~~ Done (First Assault)
3. ~~Cross-network match: Xenia joins a console host~~ Done (2026-11-11)
4. **Console joins a Xenia host.** Needs Xenia on a connection that accepts inbound
   traffic, with the same ports forwarded to the Xenia PC.
5. ~~**Standalone.** BearSSL TLS inside the plugin, so no PC is needed.~~ Done (2026-11-11)
6. ~~Faster API calls (keep-alive, DNS cache), less memory, `debug_log` setting~~ Done (2026-11-11).
   Watch for the dashboard-exit issue.
7. More games (most use plain XSession matchmaking without XHttp), presence, leaderboards.

## Credits

Protocol and behaviour come from AdrianCassar's
[Xenia Canary Netplay](https://github.com/AdrianCassar/xenia-canary) and
[Xenia-WebServices](https://github.com/AdrianCassar/Xenia-WebServices). TLS by
[BearSSL](https://bearssl.org/) (Thomas Pornin, MIT licence); root CAs from Mozilla's
bundle. LZX decompression for analysis via [libmspack](https://github.com/kyz/libmspack);
disassembly with [Capstone](https://www.capstone-engine.org/).
