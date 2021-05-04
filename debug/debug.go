package main

import (
	"errors"
	"encoding/base64"
	"fmt"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/bootfromvolume"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/schedulerhints"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/attributestags"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/trunks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	flavorutils "github.com/gophercloud/utils/openstack/compute/v2/flavors"
	imageutils "github.com/gophercloud/utils/openstack/imageservice/v2/images"
	configclient "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	openstackconfigv1 "sigs.k8s.io/cluster-api-provider-openstack/pkg/apis/openstackproviderconfig/v1alpha1"
)

type InstanceService struct {
name string
}

func main() {
print("hello world")
}

func GetSecurityGroups(is *InstanceService, sg_param []openstackconfigv1.SecurityGroupParam) ([]string, error) {
	var fakestrings []string
	fakestrings[0] = "zero"
	fakestrings[1] = "one"
	fakestrings[2] = "two"
	return fakestrings, errors.New("fake error")
}

func GetTrunkSupport(service *InstanceService)(bool, error)  {
	return true, errors.New("dummy error")
}

func (is *InstanceService) InstanceCreate(clusterName string, name string, clusterSpec *openstackconfigv1.OpenstackClusterProviderSpec, config *openstackconfigv1.OpenstackProviderSpec, cmd string, keyName string, configClient configclient.ConfigV1Interface) (instance *Instance, err error) {
	if config == nil {
		return nil, fmt.Errorf("create Options need be specified to create instace")
	}
	if config.Trunk == true {
		trunkSupport, err := GetTrunkSupport(is)
		if err != nil {
			return nil, fmt.Errorf("There was an issue verifying whether trunk support is available, please disable it: %v", err)
		}
		if trunkSupport == false {
			return nil, fmt.Errorf("There is no trunk support. Please disable it")
		}
	}

	// Set default Tags
	machineTags := []string{
		"cluster-api-provider-openstack",
		clusterName,
	}

	// Append machine specific tags
	machineTags = append(machineTags, config.Tags...)

	// Append cluster scope tags
	if clusterSpec != nil && clusterSpec.Tags != nil {
		machineTags = append(machineTags, clusterSpec.Tags...)
	}

	// Get security groups
	securityGroups, err := GetSecurityGroups(is, config.SecurityGroups)
	if err != nil {
		return nil, err
	}
	// Get all network UUIDs
	var nets []openstackconfigv1.PortOpts
	netsWithoutAllowedAddressPairs := map[string]struct{}{}
	for _, net := range config.Networks {
		opts := networks.ListOpts(net.Filter)
		opts.ID = net.UUID
		ids, err := getNetworkIDsByFilter(is, &opts)
		if err != nil {
			return nil, err
		}
		for _, netID := range ids {
			if net.NoAllowedAddressPairs {
				netsWithoutAllowedAddressPairs[netID] = struct{}{}
			}
			if net.Subnets == nil {
				nets = append(nets, openstackconfigv1.PortOpts{
					NetworkID:    netID,
					Tags:         net.PortTags,
					VNICType:     net.VNICType,
					PortSecurity: net.PortSecurity,
				})
			}

			for _, snetParam := range net.Subnets {
				sopts := subnets.ListOpts(snetParam.Filter)
				sopts.ID = snetParam.UUID
				sopts.NetworkID = netID
				// Inherit portSecurity from network if unset on subnet
				portSecurity := net.PortSecurity
				if snetParam.PortSecurity != nil {
					portSecurity = snetParam.PortSecurity
				}

				// Query for all subnets that match filters
				snetResults, err := getSubnetsByFilter(is, &sopts)
				if err != nil {
					return nil, err
				}
				for _, snet := range snetResults {
					nets = append(nets, openstackconfigv1.PortOpts{
						NetworkID:    snet.NetworkID,
						FixedIPs:     []openstackconfigv1.FixedIPs{{SubnetID: snet.ID}},
						Tags:         append(net.PortTags, snetParam.PortTags...),
						VNICType:     net.VNICType,
						PortSecurity: portSecurity,
					})
				}
			}
		}
	}

	clusterInfra, err := configClient.Infrastructures().Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve cluster Infrastructure object: %v", err)
	}

	allowedAddressPairs := []openstackconfigv1.AddressPair{}
	if clusterInfra != nil && clusterInfra.Status.PlatformStatus != nil && clusterInfra.Status.PlatformStatus.OpenStack != nil {
		clusterVips := []string{
			clusterInfra.Status.PlatformStatus.OpenStack.APIServerInternalIP,
			clusterInfra.Status.PlatformStatus.OpenStack.NodeDNSIP,
			clusterInfra.Status.PlatformStatus.OpenStack.IngressIP,
		}

		for _, vip := range clusterVips {
			if vip != "" {
				allowedAddressPairs = append(allowedAddressPairs, openstackconfigv1.AddressPair{IPAddress: vip})
			}
		}
	}

	userData := base64.StdEncoding.EncodeToString([]byte(cmd))
	var portsList []servers.Network
	for _, portOpt := range nets {
		if portOpt.NetworkID == "" {
			return nil, fmt.Errorf("A network was not found or provided for one of the networks or subnets in this machineset")
		}
		portOpt.SecurityGroups = &securityGroups
		portOpt.AllowedAddressPairs = allowedAddressPairs
		if _, ok := netsWithoutAllowedAddressPairs[portOpt.NetworkID]; ok {
			portOpt.AllowedAddressPairs = []openstackconfigv1.AddressPair{}
		}

		port, err := getOrCreatePort(is, name, portOpt)
		if err != nil {
			return nil, fmt.Errorf("Failed to create port err: %v", err)
		}

		portTags := deduplicateList(append(machineTags, portOpt.Tags...))
		_, err = attributestags.ReplaceAll(is.networkClient, "ports", port.ID, attributestags.ReplaceAllOpts{
			Tags: portTags}).Extract()
		if err != nil {
			return nil, fmt.Errorf("Tagging port for server err: %v", err)
		}
		portsList = append(portsList, servers.Network{
			Port: port.ID,
		})

		if config.Trunk == true {
			allPages, err := trunks.List(is.networkClient, trunks.ListOpts{
				Name:   name,
				PortID: port.ID,
			}).AllPages()
			if err != nil {
				return nil, fmt.Errorf("Searching for existing trunk for server err: %v", err)
			}
			trunkList, err := trunks.ExtractTrunks(allPages)
			if err != nil {
				return nil, fmt.Errorf("Searching for existing trunk for server err: %v", err)
			}
			var trunk trunks.Trunk
			if len(trunkList) == 0 {
				// create trunk with the previous port as parent
				trunkCreateOpts := trunks.CreateOpts{
					Name:   name,
					PortID: port.ID,
				}
				newTrunk, err := trunks.Create(is.networkClient, trunkCreateOpts).Extract()
				if err != nil {
					return nil, fmt.Errorf("Create trunk for server err: %v", err)
				}
				trunk = *newTrunk
			} else {
				trunk = trunkList[0]
			}

			_, err = attributestags.ReplaceAll(is.networkClient, "trunks", trunk.ID, attributestags.ReplaceAllOpts{
				Tags: machineTags}).Extract()
			if err != nil {
				return nil, fmt.Errorf("Tagging trunk for server err: %v", err)
			}
		}
	}

	for _, portCreateOpts := range config.Ports {
		port, err := getOrCreatePort(is, name+"-"+portCreateOpts.NameSuffix, portCreateOpts)
		if err != nil {
			return nil, err
		}

		portTags := deduplicateList(append(machineTags, portCreateOpts.Tags...))
		_, err = attributestags.ReplaceAll(is.networkClient, "ports", port.ID, attributestags.ReplaceAllOpts{
			Tags: portTags}).Extract()
		if err != nil {
			return nil, fmt.Errorf("Tagging port for server err: %v", err)
		}

		portsList = append(portsList, servers.Network{
			Port: port.ID,
		})
	}

	if len(portsList) == 0 {
		return nil, fmt.Errorf("At least one network, subnet, or port must be defined as a networking interface. Please review your machineset and try again")
	}

	var serverTags []string
	if clusterSpec.DisableServerTags == false {
		serverTags = machineTags
		// NOTE(flaper87): This is the minimum required version
		// to use tags.
		is.computeClient.Microversion = "2.52"
	}

	var imageID string

	if config.RootVolume == nil {
		imageID, err = imageutils.IDFromName(is.imagesClient, config.Image)
		if err != nil {
			return nil, fmt.Errorf("Create new server err: %v", err)
		}
	}

	flavorID, err := flavorutils.IDFromName(is.computeClient, config.Flavor)
	if err != nil {
		return nil, fmt.Errorf("Create new server err: %v", err)
	}

	var serverCreateOpts servers.CreateOptsBuilder = servers.CreateOpts{
		Name:             name,
		ImageRef:         imageID,
		FlavorRef:        flavorID,
		AvailabilityZone: config.AvailabilityZone,
		Networks:         portsList,
		UserData:         []byte(userData),
		SecurityGroups:   securityGroups,
		Tags:             serverTags,
		Metadata:         config.ServerMetadata,
		ConfigDrive:      config.ConfigDrive,
	}

	// If the root volume Size is not 0, means boot from volume
	if config.RootVolume != nil && config.RootVolume.Size != 0 {
		var blocks []bootfromvolume.BlockDevice

		volumeID := config.RootVolume.SourceUUID

		// change serverCreateOpts to exclude imageRef from them
		serverCreateOpts = servers.CreateOpts{
			Name:             name,
			FlavorRef:        flavorID,
			AvailabilityZone: config.AvailabilityZone,
			Networks:         portsList,
			UserData:         []byte(userData),
			SecurityGroups:   securityGroups,
			Tags:             serverTags,
			Metadata:         config.ServerMetadata,
			ConfigDrive:      config.ConfigDrive,
		}

		if bootfromvolume.SourceType(config.RootVolume.SourceType) == bootfromvolume.SourceImage {
			// if source type is "image" then we have to create a volume from the image first
			klog.Infof("Creating a bootable volume from image %v.", config.RootVolume.SourceUUID)

			imageID, err := imageutils.IDFromName(is.imagesClient, config.RootVolume.SourceUUID)
			if err != nil {
				return nil, fmt.Errorf("Create new server err: %v", err)
			}

			// Create a volume first
			volumeCreateOpts := volumes.CreateOpts{
				Size:       config.RootVolume.Size,
				VolumeType: config.RootVolume.VolumeType,
				ImageID:    imageID,
				// The same name as the instance
				Name:             name,
				AvailabilityZone: config.RootVolume.Zone,
			}

			volume, err := volumes.Create(is.volumeClient, volumeCreateOpts).Extract()
			if err != nil {
				return nil, fmt.Errorf("Create bootable volume err: %v", err)
			}

			volumeID = volume.ID

			err = volumes.WaitForStatus(is.volumeClient, volumeID, "available", 300)
			if err != nil {
				klog.Infof("Bootable volume %v creation failed. Removing...", volumeID)
				err = volumes.Delete(is.volumeClient, volumeID, volumes.DeleteOpts{}).ExtractErr()
				if err != nil {
					return nil, fmt.Errorf("Bootable volume deletion err: %v", err)
				}

				return nil, fmt.Errorf("Bootable volume %v is not available err: %v", volumeID, err)
			}

			klog.Infof("Bootable volume %v was created successfully.", volumeID)
		}

		block := bootfromvolume.BlockDevice{
			SourceType:          bootfromvolume.SourceVolume,
			BootIndex:           0,
			UUID:                volumeID,
			DeleteOnTermination: true,
			DestinationType:     bootfromvolume.DestinationVolume,
		}
		blocks = append(blocks, block)

		serverCreateOpts = bootfromvolume.CreateOptsExt{
			CreateOptsBuilder: serverCreateOpts,
			BlockDevice:       blocks,
		}

	}

	// The Machine spec accepts both a server group ID and a server group
	// name. If both are present, assert that they are consistent, else
	// fail. If only the name is present, create the server group.
	//
	// This block validates or populates config.ServerGroupID.
	if config.ServerGroupName != "" {
		existingServerGroups, err := getServerGroupsByName(is.computeClient, config.ServerGroupName)
		if err != nil {
			return nil, fmt.Errorf("retrieving existing server groups: %v", err)
		}

		if config.ServerGroupID == "" {
			switch len(existingServerGroups) {
			case 0:
				sg, err := createServerGroup(is.computeClient, config.ServerGroupName)
				if err != nil {
					return nil, fmt.Errorf("creating the server group: %v", err)
				}
				config.ServerGroupID = sg.ID
			case 1:
				config.ServerGroupID = existingServerGroups[0].ID
			default:
				return nil, fmt.Errorf("multiple server groups found with the same ServerGroupName")
			}
		} else {
			switch len(existingServerGroups) {
			case 0:
				return nil, fmt.Errorf("incompatible ServerGroupID and ServerGroupName")
			default:
				var found bool
				for _, existingServerGroup := range existingServerGroups {
					if existingServerGroup.ID == config.ServerGroupID {
						found = true
						break
					}
				}
				if !found {
					return nil, fmt.Errorf("incompatible ServerGroupID and ServerGroupName")
				}
			}
		}
	}

	// If the spec sets a server group, then add scheduler hint
	if config.ServerGroupID != "" {
		serverCreateOpts = schedulerhints.CreateOptsExt{
			CreateOptsBuilder: serverCreateOpts,
			SchedulerHints: schedulerhints.SchedulerHints{
				Group: config.ServerGroupID,
			},
		}
	}

	server, err := servers.Create(is.computeClient, keypairs.CreateOptsExt{
		CreateOptsBuilder: serverCreateOpts,
		KeyName:           keyName,
	}).Extract()
	if err != nil {
		return nil, fmt.Errorf("Create new server err: %v", err)
	}

	is.computeClient.Microversion = ""
	return serverToInstance(server), nil
}
