package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

const RecursionDesired uint16 = 1 << 8
const ClassIn = 1

func executeQuery(address string, name string, recordType uint16) (dnsPacket, error) {
	query, err := buildQuery(name, recordType)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("failed to build query: %v", err)
	}
	conn, err := net.Dial("udp", address)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("failed to open connection: %v", err)
	}
	defer conn.Close()
	_, err = conn.Write(query)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("failed to write query: %v", err)
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("failed to read response: %v", err)
	}
	reader := bytes.NewReader(resp[:n])
	packet, err := parsePacket(reader)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("failed to parse packet: %v", err)
	}
	return packet, nil
}

func buildQuery(domainName string, recordType uint16) ([]byte, error) {
	query := []byte{}
	name, err := encodeDNSName(domainName)
	if err != nil {
		return query, fmt.Errorf("encoding dns name: %w", err)
	}
	header, err := dnsHeader{
		Id:           1,
		Flags:        RecursionDesired,
		NumQuestions: 1,
	}.toBytes()
	if err != nil {
		return query, fmt.Errorf("building header: %w", err)
	}
	query = append(query, header...)
	question, err := dnsQuestion{
		Name:  name,
		Type_: recordType,
		Class: ClassIn,
	}.toBytes()
	if err != nil {
		return query, fmt.Errorf("building question: %w", err)
	}
	query = append(query, question...)
	return query, nil
}

func encodeDNSName(domainName string) ([]byte, error) {
	data := []byte{}
	for part := range strings.SplitSeq(domainName, ".") {
		if len(part) > 63 {
			return nil, fmt.Errorf("label %q exceeds 63 bytes", part)
		}
		data = append(data, byte(len(part)))
		data = append(data, []byte(part)...)
	}
	data = append(data, byte(0))
	return data, nil
}

type dnsHeader struct {
	Id             uint16
	Flags          uint16
	NumQuestions   uint16
	NumAnswers     uint16
	NumAuthorities uint16
	NumAdditionals uint16
}

func (h dnsHeader) toBytes() ([]byte, error) {
	return binary.Append([]byte{}, binary.BigEndian, h)
}

type dnsQuestion struct {
	Name  []byte
	Type_ uint16
	Class uint16
}

func (q dnsQuestion) toBytes() ([]byte, error) {
	data := append([]byte{}, q.Name...)
	return binary.Append(data, binary.BigEndian, struct{ Type, Class uint16 }{q.Type_, q.Class})
}

func (q dnsQuestion) toString() string {
	return fmt.Sprintf("{Name: %s, Type_: %v, Class: %v}", q.Name, q.Type_, q.Class)
}

type dnsRecord struct {
	Name  []byte
	Type_ uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

func (r *dnsRecord) toString() string {
	return fmt.Sprintf("{Name: %s, Type_: %v, Class: %v, TTL: %v, Data: %v}", r.Name, r.Type_, r.Class, r.TTL, r.Data)
}

type dnsPacket struct {
	header      dnsHeader
	questions   []dnsQuestion
	answers     []dnsRecord
	authorities []dnsRecord
	additionals []dnsRecord
}

func (p *dnsPacket) toString() string {
	header := fmt.Sprintf("{Id: %v, Flags: %v, NumQuestions: %v, NumAnswers: %v, NumAuthorities: %v, NumAdditionals: %v}", p.header.Id, p.header.Flags, p.header.NumQuestions, p.header.NumAnswers, p.header.NumAuthorities, p.header.NumAdditionals)
	questions := []string{}
	for _, q := range p.questions {
		questions = append(questions, q.toString())
	}
	answers := []string{}
	for _, a := range p.answers {
		answers = append(answers, a.toString())
	}
	authorities := []string{}
	for _, a := range p.authorities {
		authorities = append(authorities, a.toString())
	}
	additionals := []string{}
	for _, a := range p.additionals {
		additionals = append(additionals, a.toString())
	}
	return fmt.Sprintf("Packet: {\n  Header:      %v\n  Questions:   %v\n  Answers:     %v\n  Authorities: %v\n  Additionals: %v\n}", header, questions, answers, authorities, additionals)
}

func parsePacket(r io.ReadSeeker) (dnsPacket, error) {
	header, err := parseHeader(r)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("parsing packet header: %w", err)
	}
	questions, err := parseQuestions(r, header.NumQuestions)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("parsing packet questions: %w", err)
	}
	answers, err := parseRecords(r, header.NumAnswers)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("parsing packet answers: %w", err)
	}
	authorities, err := parseRecords(r, header.NumAuthorities)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("parsing packet authorities: %w", err)
	}
	additionals, err := parseRecords(r, header.NumAdditionals)
	if err != nil {
		return dnsPacket{}, fmt.Errorf("parsing packet additionals: %w", err)
	}
	return dnsPacket{
		header,
		questions,
		answers,
		authorities,
		additionals,
	}, nil
}

func parseHeader(r io.Reader) (dnsHeader, error) {
	return parseFixed[dnsHeader](r)
}

func parseQuestions(r io.ReadSeeker, n uint16) ([]dnsQuestion, error) {
	questions := []dnsQuestion{}
	for range n {
		question, err := parseQuestion(r)
		if err != nil {
			return []dnsQuestion{}, fmt.Errorf("parsing question: %v", err)
		}
		questions = append(questions, question)
	}
	return questions, nil

}

func parseQuestion(r io.ReadSeeker) (dnsQuestion, error) {
	name, err := parseName(r)
	if err != nil {
		return dnsQuestion{}, fmt.Errorf("parsing question name: %w", err)
	}
	type_, err := parseFixed[uint16](r)
	if err != nil {
		return dnsQuestion{}, fmt.Errorf("parsing question type: %w", err)
	}
	class, err := parseFixed[uint16](r)
	if err != nil {
		return dnsQuestion{}, fmt.Errorf("parsing question class: %w", err)
	}
	return dnsQuestion{
		Name:  name,
		Type_: type_,
		Class: class,
	}, nil
}

func parseRecords(r io.ReadSeeker, n uint16) ([]dnsRecord, error) {
	records := []dnsRecord{}
	for range n {
		record, err := parseRecord(r)
		if err != nil {
			return []dnsRecord{}, fmt.Errorf("parsing records: %v", err)
		}
		records = append(records, record)
	}
	return records, nil

}

func parseRecord(r io.ReadSeeker) (dnsRecord, error) {
	name, err := parseName(r)
	if err != nil {
		return dnsRecord{}, fmt.Errorf("parsing record name: %w", err)
	}
	type_, err := parseFixed[uint16](r)
	if err != nil {
		return dnsRecord{}, fmt.Errorf("parsing record type: %w", err)
	}
	class, err := parseFixed[uint16](r)
	if err != nil {
		return dnsRecord{}, fmt.Errorf("parsing record class: %w", err)
	}
	ttl, err := parseFixed[uint32](r)
	if err != nil {
		return dnsRecord{}, fmt.Errorf("parsing record ttl: %w", err)
	}

	data, err := parseData(r)
	if err != nil {
		return dnsRecord{}, fmt.Errorf("parsing record data: %w", err)
	}
	return dnsRecord{
		name,
		type_,
		class,
		ttl,
		data,
	}, nil

}

func parseName(r io.ReadSeeker) ([]byte, error) {
	var length uint8
	name := []byte{}
	for true {
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return []byte{}, fmt.Errorf("parsing name part len: %w", err)
		}
		if length == 0 {
			return name, nil
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		if length&0xC0 == 0xC0 {
			res, err := parseCompressed(r, length)
			if err != nil {
				return []byte{}, fmt.Errorf("parsing compressed name: %w", err)
			}
			name = append(name, res...)
			return name, nil
		} else {
			buf := make([]byte, length)
			if _, err := io.ReadFull(r, buf); err != nil {
				return []byte{}, fmt.Errorf("parsing name part val: %w", err)
			}
			name = append(name, buf...)
		}
	}
	return []byte{}, fmt.Errorf("unreachable error when parsing name")
}

func parseCompressed(r io.ReadSeeker, pointer_l uint8) ([]byte, error) {
	pointer_r, err := parseFixed[uint8](r)
	if err != nil {
		return []byte{}, fmt.Errorf("parsing pointer part: %w", err)
	}
	// 1) chop off the leading 2 bits of the left part of the pointer
	// 2) shift it into the leading 8 bits of the 16 bit uint16
	// 3) add the right part of pointer to the trailing 8 bits of the uint16
	pointer := (uint16(pointer_l&0x3F) << 8) + uint16(pointer_r)
	// 1) save current position
	// 2) seek to pointer position
	// 3) read name
	// 4) return to current position
	curr, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return []byte{}, fmt.Errorf("parsing current position: %w", err)
	}
	_, err = r.Seek(int64(pointer), io.SeekStart)
	if err != nil {
		return []byte{}, fmt.Errorf("seeking name part val: %w", err)
	}
	name, err := parseName(r)
	if err != nil {
		return []byte{}, fmt.Errorf("parsing seeked name part val: %w", err)
	}
	_, err = r.Seek(curr, io.SeekStart)
	if err != nil {
		return []byte{}, fmt.Errorf(" seeking back from parsing name part val: %w", err)
	}
	return name, nil
}

func parseData(r io.Reader) ([]byte, error) {
	dataLen, err := parseFixed[uint16](r)
	if err != nil {
		return []byte{}, fmt.Errorf("parsing record data len: %w", err)
	}
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return []byte{}, fmt.Errorf("parsing record data: %w", err)
	}
	return data, nil
}

// Parse a fixed size value
// T must be a fixed size type
func parseFixed[T any](r io.Reader) (T, error) {
	var data T
	err := binary.Read(r, binary.BigEndian, &data)
	if err != nil {
		return data, fmt.Errorf("parsing fixed length value: %w", err)
	}
	return data, nil
}
