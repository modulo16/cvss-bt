import json
import pandas as pd
import os
import logging
from datetime import datetime
import cvss

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OCSFProcessor:
    """
    Processes Open Cybersecurity Schema Framework (OCSF) data and integrates it with CVSS scores
    to provide environment-contextualized vulnerability findings.
    """

    def __init__(self, ocsf_file_path=None):
        """
        Initialize the OCSF processor with an optional OCSF file path.
        
        Args:
            ocsf_file_path (str, optional): Path to the OCSF JSON file
        """
        self.ocsf_data = None
        self.asset_inventory = {}
        self.vulnerability_findings = {}
        
        if ocsf_file_path and os.path.exists(ocsf_file_path):
            self.load_ocsf_data(ocsf_file_path)
    
    def load_ocsf_data(self, file_path):
        """
        Load and parse OCSF JSON data.
        
        Args:
            file_path (str): Path to the OCSF JSON file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.ocsf_data = json.load(f)
            
            logger.info(f"Successfully loaded OCSF data from {file_path}")
            
            # Process the OCSF data to extract asset inventory and vulnerability findings
            self._process_ocsf_data()
            return True
        
        except Exception as e:
            logger.error(f"Error loading OCSF data: {str(e)}")
            return False
    
    def _process_ocsf_data(self):
        """
        Process the loaded OCSF data to extract asset inventory and vulnerability findings.
        """
        if not self.ocsf_data:
            logger.warning("No OCSF data available to process")
            return
        
        try:
            # Extract asset inventory
            if 'assets' in self.ocsf_data:
                for asset in self.ocsf_data['assets']:
                    asset_id = asset.get('asset_id')
                    if asset_id:
                        self.asset_inventory[asset_id] = {
                            'hostname': asset.get('hostname', 'Unknown'),
                            'ip_addresses': asset.get('ip_addresses', []),
                            'os': asset.get('os', {}),
                            'criticality': asset.get('criticality', 'Medium'),
                            'applications': asset.get('applications', [])
                        }
            
            # Extract vulnerability findings
            if 'vulnerability_findings' in self.ocsf_data:
                for finding in self.ocsf_data['vulnerability_findings']:
                    cve_id = finding.get('cve_id')
                    if cve_id:
                        if cve_id not in self.vulnerability_findings:
                            self.vulnerability_findings[cve_id] = []
                        
                        self.vulnerability_findings[cve_id].append({
                            'asset_id': finding.get('asset_id'),
                            'scan_time': finding.get('scan_time'),
                            'status': finding.get('status', 'Open'),
                            'remediation_available': finding.get('remediation_available', False),
                            'exploitation_likelihood': finding.get('exploitation_likelihood', 'Unknown')
                        })
            
            logger.info(f"Processed OCSF data: {len(self.asset_inventory)} assets and {len(self.vulnerability_findings)} unique vulnerabilities found")
        
        except Exception as e:
            logger.error(f"Error processing OCSF data: {str(e)}")
    
    def enrich_cvss_with_environmental(self, cvss_bt_df):
        """
        Enrich CVSS-BT data with environmental metrics derived from OCSF data.
        
        Args:
            cvss_bt_df (pandas.DataFrame): DataFrame containing CVSS-BT data
            
        Returns:
            pandas.DataFrame: Enriched DataFrame with environmental metrics
        """
        if not self.ocsf_data or cvss_bt_df.empty:
            return cvss_bt_df
        
        # Create a copy to avoid modifying the original DataFrame
        enriched_df = cvss_bt_df.copy()
        
        # Add columns for environmental metrics
        enriched_df['affected_assets_count'] = 0
        enriched_df['critical_assets_affected'] = False
        enriched_df['remediation_available'] = False
        enriched_df['environmental_score'] = enriched_df['cvss-bt_score']
        enriched_df['environmental_severity'] = enriched_df['cvss-bt_severity']
        enriched_df['environmental_vector'] = enriched_df['cvss-bt_vector']
        
        # Iterate through each CVE in the DataFrame
        for index, row in enriched_df.iterrows():
            cve_id = row['cve']
            
            if cve_id in self.vulnerability_findings:
                findings = self.vulnerability_findings[cve_id]
                
                # Count affected assets
                affected_assets = len(findings)
                enriched_df.at[index, 'affected_assets_count'] = affected_assets
                
                # Check if any critical assets are affected
                critical_assets_affected = False
                all_remediation_available = True
                
                for finding in findings:
                    asset_id = finding.get('asset_id')
                    if asset_id in self.asset_inventory:
                        asset = self.asset_inventory[asset_id]
                        if asset.get('criticality', '').lower() == 'high' or asset.get('criticality', '').lower() == 'critical':
                            critical_assets_affected = True
                    
                    if not finding.get('remediation_available', False):
                        all_remediation_available = False
                
                enriched_df.at[index, 'critical_assets_affected'] = critical_assets_affected
                enriched_df.at[index, 'remediation_available'] = all_remediation_available
                
                # Calculate Environmental score using CVSS vector
                try:
                    # Parse the base CVSS vector to add environmental metrics
                    base_vector = row['cvss-bt_vector']
                    cvss_version = str(row['cvss_version'])
                    
                    # Set environmental metrics based on OCSF data
                    # For critical assets, set Modified Confidentiality/Integrity/Availability to High
                    env_metrics = ""
                    
                    if '4.0' in cvss_version:
                        # CVSS v4.0 environmental metrics
                        if critical_assets_affected:
                            env_metrics = "/CR:H/IR:H/AR:H"
                        else:
                            env_metrics = "/CR:M/IR:M/AR:M"
                        
                        env_vector = f"{base_vector}{env_metrics}"
                        c = cvss.CVSS4(env_vector)
                        env_score = c.environmental_score
                        env_severity = str(c.environmental_severity).upper()
                    
                    elif '3' in cvss_version:
                        # CVSS v3.x environmental metrics
                        if critical_assets_affected:
                            env_metrics = "/CR:H/IR:H/AR:H"
                        else:
                            env_metrics = "/CR:M/IR:M/AR:M"
                        
                        # Add modified CIA if critical
                        if critical_assets_affected:
                            env_metrics += "/MAC:H/MAI:H/MAA:H"
                        
                        env_vector = f"{base_vector}{env_metrics}"
                        c = cvss.CVSS3(env_vector)
                        env_score = c.environmental_score
                        env_severity = str(c.severities()[2]).upper()
                    
                    elif '2' in cvss_version:
                        # CVSS v2 environmental metrics
                        if critical_assets_affected:
                            env_metrics = "/CDP:H/TD:H"
                        else:
                            env_metrics = "/CDP:M/TD:M"
                        
                        env_vector = f"{base_vector}{env_metrics}"
                        c = cvss.CVSS2(env_vector)
                        env_score = c.environmental_score
                        env_severity = str(c.severities()[2]).upper()
                    
                    else:
                        env_score = row['cvss-bt_score']
                        env_severity = row['cvss-bt_severity']
                        env_vector = base_vector
                    
                    # Update the DataFrame with environmental metrics
                    enriched_df.at[index, 'environmental_score'] = env_score
                    enriched_df.at[index, 'environmental_severity'] = env_severity
                    enriched_df.at[index, 'environmental_vector'] = env_vector
                
                except Exception as e:
                    logger.error(f"Error calculating environmental score for {cve_id}: {str(e)}")
        
        return enriched_df
    
    def generate_findings_report(self, enriched_df, output_file='cvss-bte.csv'):
        """
        Generate a comprehensive findings report that combines CVSS scores with environmental context.
        
        Args:
            enriched_df (pandas.DataFrame): Enriched DataFrame with CVSS and environmental data
            output_file (str): Output file path for the report
            
        Returns:
            pandas.DataFrame: The report DataFrame
        """
        # Create a prioritized list of vulnerabilities based on environmental context
        report_df = enriched_df.sort_values(by=['environmental_score', 'affected_assets_count'], ascending=False)
        
        # Add additional columns for the report
        report_df['priority'] = 'Low'
        report_df.loc[(report_df['environmental_severity'] == 'CRITICAL') & (report_df['affected_assets_count'] > 0), 'priority'] = 'Critical'
        report_df.loc[(report_df['environmental_severity'] == 'HIGH') & (report_df['affected_assets_count'] > 0), 'priority'] = 'High'
        report_df.loc[(report_df['environmental_severity'] == 'MEDIUM') & (report_df['affected_assets_count'] > 0), 'priority'] = 'Medium'
        
        # Further prioritize based on remediation availability and critical assets
        report_df.loc[(report_df['priority'] == 'High') & (report_df['critical_assets_affected']), 'priority'] = 'Critical'
        report_df.loc[(report_df['priority'] == 'Medium') & (report_df['critical_assets_affected']), 'priority'] = 'High'
        
        # Organize the columns for the report
        columns = [
            'cve',
            'priority',
            'affected_assets_count',
            'critical_assets_affected',
            'remediation_available',
            'environmental_score',
            'environmental_severity',
            'environmental_vector',
            'cvss-bt_score',
            'cvss-bt_severity',
            'cvss-bt_vector',
            'cvss_version',
            'base_score',
            'base_severity',
            'base_vector',
            'assigner',
            'published_date',
            'epss',
            'cisa_kev',
            'vulncheck_kev',
            'exploitdb',
            'metasploit',
            'nuclei',
            'poc_github'
        ]
        
        # Select only columns that exist in the DataFrame
        available_columns = [col for col in columns if col in report_df.columns]
        report_df = report_df[available_columns]
        
        # Save the report to a CSV file
        if output_file:
            report_df.to_csv(output_file, index=False)
            logger.info(f"Findings report saved to {output_file}")
        
        return report_df
    
    def generate_asset_vulnerability_matrix(self, output_file='asset_vulnerability_matrix.csv'):
        """
        Generate a matrix showing which assets are affected by which vulnerabilities.
        
        Args:
            output_file (str): Output file path for the matrix
            
        Returns:
            pandas.DataFrame: The asset vulnerability matrix
        """
        if not self.asset_inventory or not self.vulnerability_findings:
            logger.warning("No asset inventory or vulnerability findings available to generate matrix")
            return pd.DataFrame()
        
        # Create a list of all asset-vulnerability pairs
        matrix_data = []
        
        for cve_id, findings in self.vulnerability_findings.items():
            for finding in findings:
                asset_id = finding.get('asset_id')
                if asset_id in self.asset_inventory:
                    asset = self.asset_inventory[asset_id]
                    
                    matrix_data.append({
                        'cve_id': cve_id,
                        'asset_id': asset_id,
                        'hostname': asset.get('hostname', 'Unknown'),
                        'ip_addresses': ', '.join(asset.get('ip_addresses', [])),
                        'os': asset.get('os', {}).get('name', 'Unknown'),
                        'os_version': asset.get('os', {}).get('version', 'Unknown'),
                        'criticality': asset.get('criticality', 'Medium'),
                        'status': finding.get('status', 'Open'),
                        'scan_time': finding.get('scan_time', ''),
                        'remediation_available': finding.get('remediation_available', False)
                    })
        
        # Create a DataFrame from the matrix data
        matrix_df = pd.DataFrame(matrix_data)
        
        # Save the matrix to a CSV file
        if output_file and not matrix_df.empty:
            matrix_df.to_csv(output_file, index=False)
            logger.info(f"Asset vulnerability matrix saved to {output_file}")
        
        return matrix_df
