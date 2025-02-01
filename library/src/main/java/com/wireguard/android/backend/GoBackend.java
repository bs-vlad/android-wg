package com.wireguard.android.backend;

import static java.util.Collections.emptyList;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;

import com.wireguard.android.backend.BackendException.Reason;
import com.wireguard.android.backend.Tunnel.State;
import com.wireguard.android.util.SharedLibraryLoader;
import com.wireguard.config.Config;
import com.wireguard.config.InetEndpoint;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;
import com.wireguard.util.NonNullForAll;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.CompletableFuture;

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;

/**
 * Implementation of {@link Backend} that uses the wireguard-go userspace implementation to provide
 * WireGuard tunnels.
 */
@NonNullForAll
public final class GoBackend implements Backend {
    private static final int DNS_RESOLUTION_RETRIES = 10;
    private static final String TAG = "WireGuard/GoBackend";
    @Nullable
    private static AlwaysOnCallback alwaysOnCallback;
    private static CompletableFuture<VpnService> vpnService = new CompletableFuture<>();
    private final Context context;
    @Nullable
    private Config currentConfig;
    @Nullable
    private Tunnel currentTunnel;
    private int currentTunnelHandle = -1;

    /**
     * Public constructor for GoBackend.
     *
     * @param context An Android {@link Context}
     */
    public GoBackend(final Context context) {
        SharedLibraryLoader.loadSharedLibrary(context, "wg-go");
        this.context = context;
    }

    /**
     * Set a {@link AlwaysOnCallback} to be invoked when {@link VpnService} is started by the
     * system's Always-On VPN mode.
     *
     * @param cb Callback to be invoked
     */
    public static void setAlwaysOnCallback(final AlwaysOnCallback cb) {
        alwaysOnCallback = cb;
    }

    @Nullable
    private static native String wgGetConfig(int handle);

    private static native int wgGetSocketV4(int handle);

    private static native int wgGetSocketV6(int handle);

    private static native void wgTurnOff(int handle);

    private static native int wgTurnOn(String ifName, int tunFd, String settings);

    private static native String wgVersion();

    /**
     * Method to get the names of running tunnels.
     *
     * @return A set of string values denoting names of running tunnels.
     */
    @Override
    public Set<String> getRunningTunnelNames() {
        if (currentTunnel != null) {
            final Set<String> runningTunnels = new ArraySet<>();
            runningTunnels.add(currentTunnel.getName());
            return runningTunnels;
        }
        return Collections.emptySet();
    }

    /**
     * Get the associated {@link State} for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to examine the state of.
     * @return {@link State} associated with the given tunnel.
     */
    @Override
    public State getState(final Tunnel tunnel) {
        return currentTunnel == tunnel ? State.UP : State.DOWN;
    }

    /**
     * Get the associated {@link Statistics} for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to retrieve statistics for.
     * @return {@link Statistics} associated with the given tunnel.
     */
    @Override
    public Statistics getStatistics(final Tunnel tunnel) {
        final Statistics stats = new Statistics();
        if (tunnel != currentTunnel || currentTunnelHandle == -1)
            return stats;
        final String config = wgGetConfig(currentTunnelHandle);
        if (config == null)
            return stats;
        Key key = null;
        long rx = 0;
        long tx = 0;
        long latestHandshakeMSec = 0;
        for (final String line : config.split("\\n")) {
            if (line.startsWith("public_key=")) {
                if (key != null)
                    stats.add(key, rx, tx, latestHandshakeMSec);
                rx = 0;
                tx = 0;
                latestHandshakeMSec = 0;
                try {
                    key = Key.fromHex(line.substring(11));
                } catch (final KeyFormatException ignored) {
                    key = null;
                }
            } else if (line.startsWith("rx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    rx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    rx = 0;
                }
            } else if (line.startsWith("tx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    tx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    tx = 0;
                }
            } else if (line.startsWith("last_handshake_time_sec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(24)) * 1000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            } else if (line.startsWith("last_handshake_time_nsec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(25)) / 1000000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            }
        }
        if (key != null)
            stats.add(key, rx, tx, latestHandshakeMSec);
        return stats;
    }

    /**
     * Get the version of the underlying wireguard-go library.
     *
     * @return {@link String} value of the version of the wireguard-go library.
     */
    @Override
    public String getVersion() {
        return wgVersion();
    }

    /**
     * Change the state of a given {@link Tunnel}, optionally applying a given {@link Config}.
     *
     * @param tunnel The tunnel to control the state of.
     * @param state  The new state for this tunnel. Must be {@code UP}, {@code DOWN}, or
     *               {@code TOGGLE}.
     * @param config The configuration for this tunnel, may be null if state is {@code DOWN}.
     * @return {@link State} of the tunnel after state changes are applied.
     * @throws Exception Exception raised while changing tunnel state.
     */
    @Override
    public State setState(
            final Tunnel tunnel,
            State state,
            @Nullable final Config config,
            List<String> excludedPackages,
            List<String> excludedIps
    ) throws Exception {
        final State originalState = getState(tunnel);

        if (state == State.TOGGLE) {
            state = (originalState == State.UP) ? State.DOWN : State.UP;
        }

        if (state == originalState && tunnel == currentTunnel && config == currentConfig) {
            return originalState;
        }

        if (state == State.UP) {
            final Config originalConfig = currentConfig;
            final Tunnel originalTunnel = currentTunnel;

            try {
                if (currentTunnel != null) {
                    setStateInternal(currentTunnel, null, State.DOWN, emptyList(), emptyList());
                }
                setStateInternal(tunnel, config, state, excludedPackages, excludedIps);
            } catch (final Exception e) {
                if (originalTunnel != null) {
                    setStateInternal(originalTunnel, originalConfig, State.UP, emptyList(), emptyList());
                }
                throw e;
            }
        } else if (state == State.DOWN && tunnel == currentTunnel) {
            setStateInternal(tunnel, null, State.DOWN, emptyList(), emptyList());
        }

        return getState(tunnel);
    }

    private void setStateInternal(
            final Tunnel tunnel,
            @Nullable final Config config,
            final State state,
            List<String> excludedPackages,
            List<String> excludedIps
    ) throws Exception {
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);

        if (state == State.UP) {
            if (config == null)
                throw new BackendException(Reason.TUNNEL_MISSING_CONFIG);

            if (VpnService.prepare(context) != null)
                throw new BackendException(Reason.VPN_NOT_AUTHORIZED);

            final VpnService service = getVpnService();
            service.setOwner(this);

            if (currentTunnelHandle != -1) {
                Log.w(TAG, "Tunnel already up");
                return;
            }

            resolveDns(config);

            // Build config
            final String goConfig = config.toWgUserspaceString();

            // Create the vpn tunnel with android API
            final VpnService.Builder builder = service.getBuilder();
            configureVpnBuilder(builder, tunnel, config, excludedPackages, excludedIps);

            try (final ParcelFileDescriptor tun = builder.establish()) {
                if (tun == null)
                    throw new BackendException(Reason.TUN_CREATION_ERROR);
                Log.d(TAG, "Go backend " + wgVersion());
                currentTunnelHandle = wgTurnOn(tunnel.getName(), tun.detachFd(), goConfig);
            }
            if (currentTunnelHandle < 0)
                throw new BackendException(Reason.GO_ACTIVATION_ERROR_CODE, currentTunnelHandle);

            currentTunnel = tunnel;
            currentConfig = config;

            service.protect(wgGetSocketV4(currentTunnelHandle));
            service.protect(wgGetSocketV6(currentTunnelHandle));
        } else {
            if (currentTunnelHandle == -1) {
                Log.w(TAG, "Tunnel already down");
                return;
            }
            shutdownTunnel();
        }

        tunnel.onStateChange(state);
    }

    private VpnService getVpnService() throws Exception {
        if (!vpnService.isDone()) {
            Log.d(TAG, "Requesting to start VpnService");
            context.startService(new Intent(context, VpnService.class));
        }

        try {
            return vpnService.get(2, TimeUnit.SECONDS);
        } catch (final TimeoutException e) {
            throw new BackendException(Reason.UNABLE_TO_START_VPN, e);
        }
    }

    private void resolveDns(Config config) throws Exception {
        for (int i = 0; i < DNS_RESOLUTION_RETRIES; ++i) {
            boolean allResolved = true;
            for (final Peer peer : config.getPeers()) {
                final InetEndpoint ep = peer.getEndpoint().orElse(null);
                if (ep != null && ep.getResolved().orElse(null) == null) {
                    allResolved = false;
                    if (i < DNS_RESOLUTION_RETRIES - 1) {
                        Log.w(TAG, "DNS host \"" + ep.getHost() + "\" failed to resolve; trying again");
                        Thread.sleep(1000);
                        break;
                    } else {
                        throw new BackendException(Reason.DNS_RESOLUTION_FAILURE, ep.getHost());
                    }
                }
            }
            if (allResolved) break;
        }
    }

    private void configureVpnBuilder(
            VpnService.Builder builder,
            Tunnel tunnel,
            Config config,
            List<String> excludedPackages,
            List<String> excludedIps
    ) throws PackageManager.NameNotFoundException, ExecutionException, InterruptedException {
        Log.d(TAG, "Configuring VPN builder for tunnel: " + tunnel.getName());

        builder.setSession(tunnel.getName());

        // Add excluded packages
        if (excludedPackages != null && !excludedPackages.isEmpty()) {
            Log.d(TAG, "Processing excluded packages. Count: " + excludedPackages.size());
            for (String packageName : excludedPackages) {
                try {
                    builder.addDisallowedApplication(packageName);
                    Log.d(TAG, "Added " + packageName + " to disallowed applications");
                } catch (PackageManager.NameNotFoundException e) {
                    Log.w(TAG, "Package " + packageName + " not found", e);
                }
            }
        } else {
            Log.d(TAG, "No excluded packages specified");
        }

        // Process interface configuration
        Log.d(TAG, "Processing interface configuration");
        for (final String excludedApplication : config.getInterface().getExcludedApplications()) {
            builder.addDisallowedApplication(excludedApplication);
            Log.d(TAG, "Added " + excludedApplication + " to interface excluded applications");
        }

        for (final String includedApplication : config.getInterface().getIncludedApplications()) {
            builder.addAllowedApplication(includedApplication);
            Log.d(TAG, "Added " + includedApplication + " to interface included applications");
        }

        for (final InetNetwork addr : config.getInterface().getAddresses()) {
            builder.addAddress(addr.getAddress(), addr.getMask());
            Log.d(TAG, "Added interface address: " + addr.getAddress() + "/" + addr.getMask());
        }

        for (final InetAddress addr : config.getInterface().getDnsServers()) {
            builder.addDnsServer(addr.getHostAddress());
            Log.d(TAG, "Added DNS server: " + addr.getHostAddress());
        }

        for (final String dnsSearchDomain : config.getInterface().getDnsSearchDomains()) {
            builder.addSearchDomain(dnsSearchDomain);
            Log.d(TAG, "Added DNS search domain: " + dnsSearchDomain);
        }

        // Process peer configuration
        Log.d(TAG, "Processing peer configuration");
        boolean sawDefaultRoute = false;
        for (final Peer peer : config.getPeers()) {
            for (final InetNetwork addr : peer.getAllowedIps()) {
                if (addr.getMask() == 0)
                    sawDefaultRoute = true;
                builder.addRoute(addr.getAddress(), addr.getMask());
                Log.d(TAG, "Added route for peer: " + addr.getAddress() + "/" + addr.getMask());
            }
        }

        if (excludedIps != null && !excludedIps.isEmpty()) {
            Log.d(TAG, "Processing excluded IPs. Count: " + excludedIps.size());
            for (String ip : excludedIps) {
                if (ip == null || ip.trim().isEmpty()) {
                    Log.w(TAG, "Skipping empty or null excluded IP");
                    continue;
                }
                try {
                    String[] parts = ip.split("/");
                    InetAddress address = InetAddress.getByName(parts[0]);
                    int prefix = parts.length > 1 ? Integer.parseInt(parts[1]) : (address instanceof Inet6Address ? 128 : 32);
                    builder.addRoute(address, prefix);
                    Log.d(TAG, "Added excluded IP/network: " + ip);
                } catch (IllegalArgumentException e) {
                    Log.w(TAG, "Invalid IP address or prefix: " + ip, e);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to add excluded IP/network: " + ip, e);
                }
            }
        } else {
            Log.d(TAG, "No excluded IPs specified");
        }

        // "Kill-switch" semantics
        if (!(sawDefaultRoute && config.getPeers().size() == 1)) {
            builder.allowFamily(OsConstants.AF_INET);
            builder.allowFamily(OsConstants.AF_INET6);
            Log.d(TAG, "Enabled kill-switch (allowing AF_INET and AF_INET6)");
        } else {
            Log.d(TAG, "Kill-switch not enabled (saw default route with single peer)");
        }

        int mtu = config.getInterface().getMtu().orElse(1280);
        builder.setMtu(mtu);
        Log.d(TAG, "Set MTU to " + mtu);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false);
            Log.d(TAG, "Set VPN as unmetered (Android Q+)");
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            vpnService.get().setUnderlyingNetworks(null);
            Log.d(TAG, "Set underlying networks to null (Android M+)");
        }

        builder.setBlocking(true);
        Log.d(TAG, "Set VPN to blocking mode");

        Log.d(TAG, "VPN builder configuration completed");
    }

    private void shutdownTunnel() {
        int handleToClose = currentTunnelHandle;
        currentTunnel = null;
        currentTunnelHandle = -1;
        currentConfig = null;
        wgTurnOff(handleToClose);
        try {
            vpnService.get(0, TimeUnit.NANOSECONDS).stopSelf();
        } catch (final TimeoutException | ExecutionException | InterruptedException ignored) {
        }
    }

    /**
     * Callback for {@link GoBackend} that is invoked when {@link VpnService} is started by the
     * system's Always-On VPN mode.
     */
    public interface AlwaysOnCallback {
        void alwaysOnTriggered();
    }

    /**
     * {@link android.net.VpnService} implementation for {@link GoBackend}
     */
    public static class VpnService extends android.net.VpnService {
        @Nullable
        private GoBackend owner;

        public Builder getBuilder() {
            return new Builder();
        }

        @Override
        public void onCreate() {
            vpnService.complete(this);
            super.onCreate();
        }

        @Override
        public void onDestroy() {
            if (owner != null) {
                final Tunnel tunnel = owner.currentTunnel;
                if (tunnel != null) {
                    if (owner.currentTunnelHandle != -1)
                        wgTurnOff(owner.currentTunnelHandle);
                    owner.currentTunnel = null;
                    owner.currentTunnelHandle = -1;
                    owner.currentConfig = null;
                    tunnel.onStateChange(State.DOWN);
                }
            }
            vpnService = new CompletableFuture<>();
            super.onDestroy();
        }

        @Override
        public int onStartCommand(@Nullable final Intent intent, final int flags, final int startId) {
            vpnService.complete(this);
            if (intent == null || intent.getComponent() == null || !intent.getComponent().getPackageName().equals(getPackageName())) {
                Log.d(TAG, "Service started by Always-on VPN feature");
                if (alwaysOnCallback != null)
                    alwaysOnCallback.alwaysOnTriggered();
            }
            return super.onStartCommand(intent, flags, startId);
        }

        public void setOwner(final GoBackend owner) {
            this.owner = owner;
        }
    }

    private int getOptimalWorkerCount() {
        int cores = Runtime.getRuntime().availableProcessors();
        return Math.max(2, Math.min(cores, 8)); // Minimum 2, maximum 8 workers
    }

    private int getOptimalKeepaliveInterval() {
        BatteryManager batteryManager = (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);
        int batteryPercentage = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);

        if (batteryPercentage > 50) {
            return 25; // 25 seconds when battery is above 50%
        } else {
            return 60; // 60 seconds when battery is low
        }
    }

// Use this method when configuring the persistent keepalive interval

// Use this method when initializing the Go backend
}
