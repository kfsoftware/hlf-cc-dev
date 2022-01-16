// Code generated by entc, DO NOT EDIT.

package tenant

const (
	// Label holds the string label denoting the tenant type in the database.
	Label = "tenant"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// FieldMspId holds the string denoting the mspid field in the database.
	FieldMspId = "msp_id"
	// FieldSignCertCAPrivateKey holds the string denoting the signcertcaprivatekey field in the database.
	FieldSignCertCAPrivateKey = "sign_cert_ca_private_key"
	// FieldSignCertCACert holds the string denoting the signcertcacert field in the database.
	FieldSignCertCACert = "sign_cert_ca_cert"
	// FieldTlsCertCAPrivateKey holds the string denoting the tlscertcaprivatekey field in the database.
	FieldTlsCertCAPrivateKey = "tls_cert_ca_private_key"
	// FieldTlsCertCACert holds the string denoting the tlscertcacert field in the database.
	FieldTlsCertCACert = "tls_cert_ca_cert"
	// EdgeChaincodes holds the string denoting the chaincodes edge name in mutations.
	EdgeChaincodes = "chaincodes"
	// Table holds the table name of the tenant in the database.
	Table = "tenants"
	// ChaincodesTable is the table that holds the chaincodes relation/edge.
	ChaincodesTable = "chaincodes"
	// ChaincodesInverseTable is the table name for the Chaincode entity.
	// It exists in this package in order to avoid circular dependency with the "chaincode" package.
	ChaincodesInverseTable = "chaincodes"
	// ChaincodesColumn is the table column denoting the chaincodes relation/edge.
	ChaincodesColumn = "tenant_chaincodes"
)

// Columns holds all SQL columns for tenant fields.
var Columns = []string{
	FieldID,
	FieldName,
	FieldMspId,
	FieldSignCertCAPrivateKey,
	FieldSignCertCACert,
	FieldTlsCertCAPrivateKey,
	FieldTlsCertCACert,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}
