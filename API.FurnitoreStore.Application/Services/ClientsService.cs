using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using API.FornitureStore.Data;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Application.Dtos.Client;
using API.FurnitoreStore.Share;

namespace API.FurnitoreStore.Application.Services;

public class ClientsService(ApplicationDbContext _context) : IClientsService
{
    public async Task<IEnumerable<ReadClientDto>> GetAllAsync()
    {
        try
        {
            var clients = await _context.Clients
                                        .AsNoTracking()
                                        .ToListAsync();
            return clients.Select(MapToReadDto);
        }
        catch (Exception ex)
        {
            throw new Exception("Error retrieving clients", ex);
        }
    }

    public async Task<ReadClientDto?> GetByIdAsync(int id)
    {
        try
        {
            var client = await _context.Clients
                                       .AsNoTracking()
                                       .FirstOrDefaultAsync(c => c.Id == id);
            if (client == null) return null;
            return MapToReadDto(client);
        }
        catch (Exception ex)
        {
            throw new Exception("Error retrieving client", ex);
        }
    }

    public async Task<ReadClientDto> CreateAsync(CreateClientDto dto)
    {
        try
        {
            var entity = new Client
            {
                AspNetUserId = dto.AspNetUserId,
                FirstName = dto.FirstName,
                LastName = dto.LastName,
                BirthDate = dto.BirthDate,
                Phone = dto.Phone,
                Address = dto.Address
            };

            await _context.Clients.AddAsync(entity);
            await _context.SaveChangesAsync();

            return MapToReadDto(entity);
        }
        catch (Exception ex)
        {
            throw new Exception("Error creating client", ex);
        }
    }

    public async Task UpdateAsync(UpdateClientDto dto)
    {
        try
        {
            var existing = await _context.Clients.FindAsync(dto.Id);
            if (existing == null)
                throw new Exception("Client not found.");

            existing.AspNetUserId = dto.AspNetUserId;
            existing.FirstName = dto.FirstName;
            existing.LastName = dto.LastName;
            existing.BirthDate = dto.BirthDate;
            existing.Phone = dto.Phone;
            existing.Address = dto.Address;

            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            throw new Exception("Error updating client", ex);
        }
    }

    public async Task DeleteAsync(int id)
    {
        try
        {
            var existing = await _context.Clients.FindAsync(id);
            if (existing == null)
                throw new Exception("Client not found.");

            _context.Clients.Remove(existing);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            throw new Exception("Error deleting client", ex);
        }
    }

    // Manual mapping helper
    private static ReadClientDto MapToReadDto(Client c) =>
        new ReadClientDto
        {
            Id = c.Id,
            AspNetUserId = c.AspNetUserId,
            FirstName = c.FirstName ?? string.Empty,
            LastName = c.LastName ?? string.Empty,
            BirthDate = c.BirthDate,
            Phone = c.Phone ?? string.Empty,
            Address = c.Address ?? string.Empty
        };
}
